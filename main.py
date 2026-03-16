"""Main entry point.

Step 1 – Crawl avd.aliyun.com, filter by injection/deserialization CWE types,
         and keep only entries with resolvable GitHub patch URLs.
Step 2 – For each accepted entry, resolve the patch commit, clone the repo, and
         run a multi-turn LLM conversation to annotate the call-trace from the
         HTTP entry point down to the vulnerable/patched method.
         If the entry-point and the patch site are in different files the LLM
         will request those files incrementally across turns.

Configuration is read from a ``.env`` file (or real env vars); see
``.env.example`` for available keys.
"""

from __future__ import annotations

import asyncio
import logging
import re
from pathlib import Path
from typing import Optional

from aliyun_crawler.calltrace import CalltraceExplorer, TokenStats
from aliyun_crawler.commit_resolver import _COMMIT_RE, _ISSUE_RE, _PR_RE, CommitResolver
from aliyun_crawler.config import CrawlerSettings
from aliyun_crawler.crawler import AVDCrawler
from aliyun_crawler.filter import FilterPipeline
from aliyun_crawler.models import AVDCveEntry
from aliyun_crawler.storage import CrawlStorage


def _setup_logging(log_dir: str | None) -> None:
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if log_dir:
        log_path = Path(log_dir)
        log_path.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_path / "crawler.log", encoding="utf-8"))
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=handlers,
    )


logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Target CWE types – injection / deserialization / RCE families
# ---------------------------------------------------------------------------

_TARGET_CWES: set[str] = {
    "CWE-79",  # Cross-site Scripting
    "CWE-89",  # SQL Injection
    "CWE-77",  # Command Injection
    "CWE-78",  # OS Command Injection
    "CWE-94",  # Code Injection
    "CWE-502",  # Deserialization of Untrusted Data
    "CWE-22",  # Path Traversal
    "CWE-611",  # XML External Entity (XXE)
    "CWE-918",  # Server-Side Request Forgery
    "CWE-917",  # Expression Language Injection
    "CWE-74",  # Injection (generic)
}


def _extract_repo_url(patch_url: str) -> Optional[str]:
    """Return the HTTPS clone URL of the GitHub repo referenced in *patch_url*."""
    for pattern in (_COMMIT_RE, _PR_RE, _ISSUE_RE):
        m = pattern.search(patch_url)
        if m:
            return f"https://github.com/{m.group(1)}/{m.group(2)}"
    return None


# ---------------------------------------------------------------------------
# Step 1 – crawl + filter
# ---------------------------------------------------------------------------


def step1_crawl_and_filter(
    settings: CrawlerSettings,
    storage: CrawlStorage,
) -> list[AVDCveEntry]:
    """Crawl avd.aliyun.com and return filtered entries with patch URLs.

    Filters applied (AND logic):
    - CWE must be in *_TARGET_CWES*
    - At least one GitHub commit / PR / issue URL must be present
    """
    config = settings.to_crawl_config()
    crawler = AVDCrawler(config)

    pipeline = (
        FilterPipeline()
        .require(lambda e: e.cwe_id in _TARGET_CWES, name="require_target_cwe")
        .require_patch_url()
    )

    entries: list[AVDCveEntry] = []
    logger.info("=== Step 1 – crawl (max_pages=%d) ===", config.max_pages)

    for raw in crawler.crawl():
        storage.save_raw(raw)
        storage.update_last_seen_date(raw)

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

    logger.info("Step 1 complete – %d entries accepted", len(entries))
    return entries


# ---------------------------------------------------------------------------
# Step 2 – LLM calltrace annotation
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


def step2_calltrace(
    settings: CrawlerSettings,
    entries: list[AVDCveEntry],
    storage: CrawlStorage,
) -> None:
    """Run async multi-turn LLM calltrace annotation and persist enriched YAML.

    The LLM traces BACKWARDS from each patched method to the HTTP entry point.
    When the trace and the patch site are in different files the model requests
    those files incrementally across turns (up to *calltrace_max_rounds*).
    """
    if not entries:
        logger.info("No entries – skipping LLM annotation.")
        return

    logger.info("=== Step 2 – resolving patch commits for %d entries ===", len(entries))
    targets = _build_targets(entries, settings.github_token)

    if not targets:
        logger.warning("No resolvable commits – skipping LLM annotation.")
        return

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

    def _on_done(entry: AVDCveEntry, stats: TokenStats) -> None:
        storage.save_yaml(entry)
        logger.info(
            "annotated  %s  rounds=%d  tokens=%d",
            entry.CVE,
            stats.rounds,
            stats.total_tokens,
        )

    logger.info(
        "=== Step 2 – LLM annotation (%d targets, concurrency=%d) ===",
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
    logger.info(
        "Step 2 complete – %d entries annotated  total_tokens=%d",
        len(enriched),
        total.total_tokens,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    settings = CrawlerSettings()
    _setup_logging(settings.log_dir)
    storage = CrawlStorage(data_dir=settings.data_dir)

    entries = step1_crawl_and_filter(settings, storage)
    # step2_calltrace(settings, entries, storage)


if __name__ == "__main__":
    main()
