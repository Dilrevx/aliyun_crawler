"""Main entry point.

Step 1 – Crawl avd.aliyun.com and persist RAW entries only.
Step 2 – Filter RAW entries (CWE + patch-url) and emit YAML entries.
Step 3 – For accepted YAML entries, resolve patch commits and annotate calltrace.

Configuration is read from a ``.env`` file (or real env vars); see
``.env.example`` for available keys.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from aliyun_crawler.calltrace import CalltraceExplorer, TokenStats
from aliyun_crawler.commit_resolver import _COMMIT_RE, _ISSUE_RE, _PR_RE, CommitResolver
from aliyun_crawler.config import CrawlerSettings
from aliyun_crawler.crawler import AVDCrawler
from aliyun_crawler.filter import FilterPipeline
from aliyun_crawler.models import AVDCveEntry, RawAVDEntry
from aliyun_crawler.storage import CrawlStorage


def _setup_logging(log_dir: str | None) -> None:
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if log_dir:
        log_path = Path(log_dir)
        log_path.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        filename = f"{timestamp}-crawler.log"
        handlers.append(
            logging.FileHandler(
                log_path / filename,
                encoding="utf-8",
            )
        )
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=handlers,
    )


logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Target CWE types – logic vulnerability focus
# ---------------------------------------------------------------------------

_TARGET_CWES: set[str] = {
    "CWE-284",  # Improper Access Control
    "CWE-285",  # Improper Authorization
    "CWE-862",  # Missing Authorization
    "CWE-863",  # Incorrect Authorization
    "CWE-639",  # IDOR / User-Controlled Key Access
    # Non-logic families (temporarily disabled)
    # "CWE-79",   # Cross-site Scripting
    # "CWE-89",   # SQL Injection
    # "CWE-77",   # Command Injection
    # "CWE-78",   # OS Command Injection
    # "CWE-94",   # Code Injection
    # "CWE-502",  # Deserialization of Untrusted Data
    # "CWE-22",   # Path Traversal
    # "CWE-611",  # XML External Entity (XXE)
    # "CWE-918",  # Server-Side Request Forgery
    # "CWE-917",  # Expression Language Injection
    # "CWE-74",   # Injection (generic)
}

_LOGIC_KEYWORDS: tuple[str, ...] = (
    "broken access control",
    "improper access control",
    "improper authorization",
    "missing authorization",
    "idor",
    "insecure direct object reference",
    "越权",
    "权限绕过",
    "未授权",
    "访问控制",
)

_STEP1_DELAY_RANGE_OVERRIDE: tuple[float, float] | None = (0.2, 0.8)


def _extract_repo_url(patch_url: str) -> Optional[str]:
    """Return the HTTPS clone URL of the GitHub repo referenced in *patch_url*."""
    for pattern in (_COMMIT_RE, _PR_RE, _ISSUE_RE):
        m = pattern.search(patch_url)
        if m:
            return f"https://github.com/{m.group(1)}/{m.group(2)}"
    return None


def _is_logic_vulnerability(entry: RawAVDEntry) -> bool:
    """Heuristic for logic vulnerabilities.

    Not equivalent to pure CWE filtering:
    - CWE match is high precision but may miss entries with noisy/missing CWE tags.
    - Keyword match improves recall but may include some false positives.
    """
    if entry.cwe_id in _TARGET_CWES:
        return True

    text = " ".join(
        [
            entry.title or "",
            entry.description or "",
            entry.cwe_description or "",
        ]
    ).lower()
    return any(keyword in text for keyword in _LOGIC_KEYWORDS)


# ---------------------------------------------------------------------------
# Step 1 – crawl raw only
# ---------------------------------------------------------------------------


def step1_crawl_to_raw(
    settings: CrawlerSettings,
    storage: CrawlStorage,
) -> list[str]:
    """Crawl avd.aliyun.com and persist RAW entries only.

    Returns:
        CVE IDs crawled in the current run.
    """
    config = settings.to_crawl_config()
    if _STEP1_DELAY_RANGE_OVERRIDE is not None:
        config.delay_range = _STEP1_DELAY_RANGE_OVERRIDE
        logger.info("Step 1 speed tuning: delay_range=%s", config.delay_range)

    storage.mark_stage1_start(
        max_pages=config.max_pages,
        page_concurrency=config.page_concurrency,
    )

    crawler = AVDCrawler(config)

    crawled_cves: list[str] = []
    started = time.perf_counter()
    logger.info("=== Step 1 – crawl raw (max_pages=%d) ===", config.max_pages)

    try:
        for raw in crawler.crawl():
            storage.save_raw(raw)
            storage.update_last_seen_date(raw)
            crawled_cves.append(raw.cve_id)
    except Exception:
        storage.mark_stage1_end(status="failed")
        raise

    elapsed = max(time.perf_counter() - started, 1e-6)
    logger.info(
        "Step 1 complete – %d raw entries persisted in %.1fs (%.2f entries/s)",
        len(crawled_cves),
        elapsed,
        len(crawled_cves) / elapsed,
    )
    storage.mark_stage1_end(status="completed")
    return crawled_cves


# ---------------------------------------------------------------------------
# Step 2 – filter raw to yaml
# ---------------------------------------------------------------------------


def _list_raw_cve_ids(storage: CrawlStorage) -> list[str]:
    """List all CVE IDs present in raw storage."""
    return sorted(p.stem for p in storage.raw_dir.glob("CVE-*.json"))


def _list_yaml_entries(storage: CrawlStorage) -> list[AVDCveEntry]:
    """Load all existing YAML entries from storage."""
    entries: list[AVDCveEntry] = []
    for cve_id in storage.list_yaml_cve_ids():
        item = storage.load_yaml(cve_id)
        if item is not None:
            entries.append(item)
    return entries


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def step2_filter_raw_to_yaml(
    storage: CrawlStorage,
    cve_ids: list[str],
) -> list[AVDCveEntry]:
    """Filter raw entries and persist accepted results to YAML.

    Filters applied (AND logic):
    - Entry matches logic-vuln heuristic (CWE set + keyword backstop)
    - At least one GitHub commit / PR / issue URL must be present
    """
    pipeline = (
        FilterPipeline()
        .require(_is_logic_vulnerability, name="require_logic_vuln")
        .require_patch_url()
    )

    dedup_cve_ids = list(dict.fromkeys(cve_ids))
    logger.info("=== Step 2 – filter raw to yaml (cves=%d) ===", len(dedup_cve_ids))

    entries: list[AVDCveEntry] = []
    for cve_id in dedup_cve_ids:
        raw = storage.load_raw(cve_id)
        if raw is None:
            continue

        if pipeline.passes(raw):
            entry = AVDCveEntry.from_raw(raw)
            storage.save_yaml(entry)
            entries.append(entry)
            logger.info(
                "accepted  %s  cwe=%-10s  patches=%d",
                raw.cve_id,
                raw.cwe_id,
                len(raw.patch_urls),
            )
        else:
            logger.debug("filtered  %s  cwe=%s", raw.cve_id, raw.cwe_id)

    logger.info(
        "Step 2 complete – %d entries accepted from %d raw entries",
        len(entries),
        len(dedup_cve_ids),
    )
    storage.mark_stage2_summary(
        input_raw_count=len(dedup_cve_ids),
        accepted_yaml_count=len(entries),
    )
    return entries


# ---------------------------------------------------------------------------
# Step 3 – LLM calltrace annotation
# ---------------------------------------------------------------------------


def _build_targets(
    entries: list[AVDCveEntry],
    github_token: Optional[str],
) -> list[tuple[AVDCveEntry, str, str]]:
    """Resolve each entry's patch URL(s) to (entry, repo_url, commit_sha)."""
    targets: list[tuple[AVDCveEntry, str, str]] = []

    with CommitResolver(github_token=github_token) as resolver:
        for entry in entries:
            resolved = False
            for patch_url in entry.patch_urls:
                repo_url = _extract_repo_url(patch_url)
                if not repo_url:
                    continue
                commits = resolver.resolve(patch_url)
                if commits:
                    targets.append((entry, repo_url, commits[0]))
                    logger.info(
                        "resolved  %s  →  %s  @  %s",
                        entry.CVE,
                        repo_url,
                        commits[0][:12],
                    )
                    resolved = True
                    break  # one commit per entry is enough

            if not resolved:
                logger.warning("no resolvable patch commit for %s", entry.CVE)

    return targets


def step3_calltrace(
    settings: CrawlerSettings,
    entries: list[AVDCveEntry],
    storage: CrawlStorage,
) -> tuple[int, int]:
    """Run async multi-turn LLM calltrace annotation and persist enriched YAML.

    The LLM traces BACKWARDS from each patched method to the HTTP entry point.
    When the trace and the patch site are in different files the model requests
    those files incrementally across turns (up to *calltrace_max_rounds*).
    """
    if not entries:
        logger.info("No entries – skipping LLM annotation.")
        return 0, 0

    logger.info("=== Step 3 – resolving patch commits for %d entries ===", len(entries))
    targets = _build_targets(entries, settings.github_token)

    if not targets:
        logger.warning("No resolvable commits – skipping LLM annotation.")
        return len(entries), 0

    repos_dir = str(Path(settings.data_dir) / "repos")
    explorer = CalltraceExplorer(
        repos_dir=repos_dir,
        llm_model=settings.llm_model,
        llm_api_key=settings.llm_api_key,
        llm_base_url=settings.llm_base_url,
        clone_via_ssh=settings.git_clone_via_ssh,
        git_proxy=settings.git_proxy,
        max_llm_rounds=settings.calltrace_max_rounds,
    )
    calltrace_subdir = settings.calltrace_output_subdir

    def _on_done(entry: AVDCveEntry, stats: TokenStats) -> None:
        storage.save_yaml_to_subdir(entry, calltrace_subdir)
        logger.info(
            "annotated  %s  rounds=%d  tokens=%d  out=%s/%s.yaml",
            entry.CVE,
            stats.rounds,
            stats.total_tokens,
            calltrace_subdir,
            entry.CVE,
        )

    logger.info(
        "=== Step 3 – LLM annotation (%d targets, concurrency=%d) ===",
        len(targets),
        settings.calltrace_concurrency,
    )
    enriched = asyncio.run(
        explorer.explore_many(
            targets,
            concurrency=settings.calltrace_concurrency,
            on_done=_on_done,
        )
    )

    total = explorer.total_stats()
    annotated_count = sum(1 for item in enriched if item.CallTrace is not None)
    logger.info(
        "Step 3 complete – %d/%d entries annotated  total_tokens=%d",
        annotated_count,
        len(targets),
        total.total_tokens,
    )
    storage.mark_stage3_summary(
        target_count=len(targets),
        annotated_count=annotated_count,
    )
    return len(targets), annotated_count


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    settings = CrawlerSettings()
    _setup_logging(settings.log_dir)
    storage = CrawlStorage(data_dir=settings.data_dir)

    run_step1_crawl_raw = _env_bool("RUN_STEP1_CRAWL_RAW", True)
    run_step2_filter_yaml = _env_bool("RUN_STEP2_FILTER_YAML", True)
    run_step3_calltrace = _env_bool("RUN_STEP3_CALLTRACE", False)

    crawled_cves: list[str] = []
    if run_step1_crawl_raw:
        crawled_cves = step1_crawl_to_raw(settings, storage)
    else:
        logger.info("Step 1 skipped (run_step1_crawl_raw=False)")

    entries: list[AVDCveEntry] = []
    if run_step2_filter_yaml:
        if not crawled_cves:
            crawled_cves = _list_raw_cve_ids(storage)
            logger.info(
                "Step 2 uses existing raw files (count=%d)",
                len(crawled_cves),
            )
        entries = step2_filter_raw_to_yaml(storage, crawled_cves)
    else:
        logger.info("Step 2 skipped (run_step2_filter_yaml=False)")

    if run_step3_calltrace and not entries:
        entries = _list_yaml_entries(storage)
        logger.info(
            "Step 3 uses existing yaml files (count=%d)",
            len(entries),
        )

    if run_step3_calltrace:
        step3_calltrace(settings, entries, storage)
    else:
        logger.info("Step 3 skipped (run_step3_calltrace=False)")


if __name__ == "__main__":
    main()
