"""LLM-driven calltrace exploration.

Given a CVE entry with a known patch commit, this module:

1. Clones (or reuses a cached clone of) the affected repository.
2. ``git checkout``s the vulnerable version (parent of the patch commit).
3. Calls ``git diff`` on the patch commit to identify patched files and methods.
4. Uses an LLM in a **multi-turn conversation** to trace backwards from the
   patched methods to the HTTP/RPC entry points.  The model may request
   additional source files each turn to extend the call chain until it reaches
   an entry point or the max-round limit is hit.
5. Writes the ``before_traces`` / ``after_traces`` fields and the
   ``patch_method_before`` / ``patch_method_after`` fields into the
   :class:`~aliyun_crawler.models.AVDCveEntry`.

Multiple CVEs are processed concurrently via
:meth:`CalltraceExplorer.explore_many`; per-repository ``asyncio.Lock``\s
ensure git state is never corrupted by concurrent checkouts of the same clone.

The Git operations are performed via :mod:`subprocess` (``git`` CLI) rather
than a Python Git library to keep dependencies minimal.

Environment / config keys (read from ``.env``)::

    LLM__PROVIDER=openai
    LLM__MODEL=deepseek-v3.2
    LLM__API_KEY=sk-...
    LLM__BASE_URL=https://api.openai.com/v1        # optional
    CRAWL__REPOS_DIR=./data/repos                  # where clones are stored
    CRAWL__CALLTRACE_CONCURRENCY=5                 # parallel CVEs
    CRAWL__CALLTRACE_MAX_ROUNDS=4                  # max LLM conversation turns
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
import os
import re
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

from aliyun_crawler.models import AVDCveEntry, CallTraceData, PatchMethod, TraceFrame

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Token statistics
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class TokenStats:
    """Per-CVE LLM token usage accumulated across all conversation rounds."""

    cve_id: str = ""
    rounds: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens

    def cost_usd(self, model: str) -> float:
        """Estimated dollar cost using the shared pricing table."""
        try:
            from route_hacker.utils.token_cost import estimate_cost

            return estimate_cost(self.prompt_tokens, self.completion_tokens, model)
        except Exception:
            return 0.0

    def __add__(self, other: "TokenStats") -> "TokenStats":
        return TokenStats(
            cve_id="total",
            rounds=self.rounds + other.rounds,
            prompt_tokens=self.prompt_tokens + other.prompt_tokens,
            completion_tokens=self.completion_tokens + other.completion_tokens,
        )


# ---------------------------------------------------------------------------
# LLM client (async, multi-turn)
# ---------------------------------------------------------------------------


class _AsyncLLMClient:
    """Async OpenAI-compatible multi-turn chat client."""

    def __init__(
        self,
        model: str = "deepseek-v3.2",
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
    ) -> None:
        self.model = model
        try:
            from openai import AsyncOpenAI  # type: ignore

            kwargs: dict[str, Any] = {}
            if api_key:
                kwargs["api_key"] = api_key
            if base_url:
                kwargs["base_url"] = base_url
            self._client = AsyncOpenAI(**kwargs)
        except ImportError:
            logger.error(
                "openai package not installed. Calltrace exploration unavailable."
            )
            self._client = None

    async def chat(
        self,
        messages: list[dict[str, str]],
        max_tokens: int = 4096,
    ) -> tuple[str, int, int]:
        """Send *messages* and return ``(text, prompt_tokens, completion_tokens)``."""
        if self._client is None:
            return "", 0, 0
        response = await self._client.chat.completions.create(
            model=self.model,
            messages=messages,  # type: ignore[arg-type]
            max_tokens=max_tokens,
            temperature=0.1,
        )
        text = response.choices[0].message.content or ""
        usage = response.usage
        p_tok = usage.prompt_tokens if usage else 0
        c_tok = usage.completion_tokens if usage else 0
        return text, p_tok, c_tok


# ---------------------------------------------------------------------------
# Git helpers
# ---------------------------------------------------------------------------


def _run_git(
    args: list[str],
    cwd: Path,
    check: bool = True,
    proxy: Optional[str] = None,
) -> subprocess.CompletedProcess:
    cmd = ["git"] + args
    logger.debug("git %s (cwd=%s)", " ".join(args[:4]), cwd)
    env = os.environ.copy()
    if proxy:
        env["HTTP_PROXY"] = proxy
        env["HTTPS_PROXY"] = proxy
    return subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=check,
        env=env if proxy else None,
    )


def _to_ssh_url(https_url: str) -> str:
    """Convert a GitHub HTTPS clone URL to its SSH equivalent.

    ``https://github.com/owner/repo.git`` → ``git@github.com:owner/repo.git``
    Non-GitHub URLs are returned unchanged.
    """
    m = re.match(r"https://github\.com/([^/]+/.+)", https_url)
    if m:
        return f"git@github.com:{m.group(1)}"
    return https_url


def _clone_or_update(
    repo_url: str,
    repos_dir: Path,
    clone_via_ssh: bool = False,
    git_proxy: Optional[str] = None,
) -> Path:
    """Clone *repo_url* under *repos_dir* if not already cloned; else fetch."""
    # Derive local directory name from repo URL
    parsed = urlparse(repo_url)
    parts = parsed.path.strip("/").split("/")
    if len(parts) < 2:
        raise ValueError(f"Cannot derive repo name from URL: {repo_url}")
    local_name = f"{parts[0]}__{parts[1]}"
    local_path = repos_dir / local_name

    effective_url = _to_ssh_url(repo_url) if clone_via_ssh else repo_url

    if local_path.exists():
        logger.info("Repo already cloned at %s; fetching…", local_path)
        _run_git(
            ["fetch", "--all", "--prune"], cwd=local_path, check=False, proxy=git_proxy
        )
    else:
        logger.info("Cloning %s → %s", effective_url, local_path)
        repos_dir.mkdir(parents=True, exist_ok=True)
        _run_git(
            ["clone", "--filter=blob:none", effective_url, local_name],
            cwd=repos_dir,
            proxy=git_proxy,
        )

    return local_path


def _checkout(repo_path: Path, ref: str) -> None:
    """Detach HEAD at *ref* (commit SHA, tag, or branch)."""
    _run_git(["checkout", "--detach", ref], cwd=repo_path)


def _get_parent_commit(repo_path: Path, commit_sha: str) -> Optional[str]:
    """Return the parent (pre-patch) commit SHA."""
    result = _run_git(["rev-parse", f"{commit_sha}^"], cwd=repo_path, check=False)
    if result.returncode == 0:
        return result.stdout.strip()
    return None


def _get_diff(repo_path: Path, commit_sha: str) -> str:
    """Return the full unified diff for *commit_sha*."""
    result = _run_git(
        ["diff", f"{commit_sha}^", commit_sha, "--unified=10"],
        cwd=repo_path,
        check=False,
    )
    return result.stdout


def _parse_diff_files(diff: str) -> list[str]:
    """Extract file paths changed in *diff*."""
    files: list[str] = []
    for m in re.finditer(r"^\+\+\+ b/(.+)$", diff, re.MULTILINE):
        files.append(m.group(1))
    return files


def _file_content(repo_path: Path, rel_path: str) -> str:
    """Read the current (checked-out) content of a repo file."""
    full = repo_path / rel_path
    if not full.exists():
        return ""
    try:
        return full.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


# ---------------------------------------------------------------------------
# Diff-to-PatchMethod parser
# ---------------------------------------------------------------------------

# More robust: extract changed line ranges and map to method names by reading
# the file content.


def _extract_patch_methods(
    diff: str, repo_path: Path
) -> tuple[list[PatchMethod], list[PatchMethod]]:
    """Parse a git diff to produce before/after :class:`PatchMethod` lists.

    Returns ``(before_methods, after_methods)``.
    Method names are extracted from hunk headers (``@@ ... @@ methodName``).
    """
    before: list[PatchMethod] = []
    after: list[PatchMethod] = []

    current_file = ""
    # Track line numbers
    before_start = 0
    after_start = 0

    for line in diff.splitlines():
        if line.startswith("--- a/"):
            current_file = line[6:]
        elif line.startswith("+++ b/"):
            current_file = line[6:]
        elif line.startswith("@@"):
            # @@ -L1,N1 +L2,N2 @@ optional_method
            hunk_m = re.match(r"@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@\s*(.*)", line)
            if not hunk_m:
                continue
            before_start = int(hunk_m.group(1))
            after_start = int(hunk_m.group(2))
            method_hint = hunk_m.group(3).strip()

            # Extract method name from hint (may be signature)
            method_name = ""
            mn = re.search(r"(\w+)\s*\(", method_hint)
            if mn:
                method_name = mn.group(1)
            elif method_hint:
                method_name = method_hint.split()[0] if method_hint.split() else ""

            if current_file and method_name:
                before.append(
                    PatchMethod(
                        file=current_file,
                        method=method_name,
                        start_line=before_start,
                        end_line=before_start,  # will be refined below
                    )
                )
                after.append(
                    PatchMethod(
                        file=current_file,
                        method=method_name,
                        start_line=after_start,
                        end_line=after_start,
                    )
                )

    # Deduplicate by (file, method)
    def _dedup(methods: list[PatchMethod]) -> list[PatchMethod]:
        seen: set[tuple] = set()
        out: list[PatchMethod] = []
        for m in methods:
            key = (m.file, m.method)
            if key not in seen:
                seen.add(key)
                out.append(m)
        return out

    return _dedup(before), _dedup(after)


# ---------------------------------------------------------------------------
# LLM prompts
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are a senior security researcher specialising in Java / web application
vulnerability analysis.

## Your task
Trace the data flow BACKWARDS from each patched method up to the HTTP / RPC
entry point (controller, filter, servlet handler, etc.), producing a structured
calltrace that shows the complete path a malicious input can travel.

## Multi-turn protocol
You may request additional source files when you need to trace callers further
up the call chain.  To request files respond with **only** this JSON:
  {"files_needed": ["path/to/Caller.java", ...]}
(all paths relative to the repository root)

Once you have sufficient context, respond with the **final** JSON (no markdown,
no prose):
{
  "before_traces": [
    [
      {"depth": 0, "file": "<repo-path>", "method": "<name>", "start_line": N, "end_line": N},
      ...
    ]
  ],
  "after_traces": [
    [ ...same structure reflecting the patched code... ]
  ],
  "source": ["<entry-point description>"],
  "sink":   ["<dangerous sink description>"],
  "reason": "<concise explanation of the vulnerability and the fix>"
}

Rules:
- depth 0 = HTTP entry point (controller / filter); increasing depth = callee.
- Include the patched method(s) as the deepest frame(s).
- Use repository-relative file paths (not absolute paths).
- Use 0 for unknown line numbers.
- Do not include calls to external libraries.
"""


def _build_user_prompt(
    entry: AVDCveEntry,
    diff: str,
    file_contents: dict[str, str],
) -> str:
    file_sections = "\n\n".join(
        f"### FILE: {path}\n```\n{content[:8000]}\n```"
        for path, content in file_contents.items()
    )
    return f"""\
CVE: {entry.CVE}
CWE: {entry.CWE} – {entry.CWEDescription}
Description: {entry.CVEDescription}

## Patch diff
```diff
{diff[:6000]}
```

## Patched file contents (after patch)
{file_sections}

Analyse the above and produce the JSON calltrace.
"""


def _parse_llm_response(
    text: str,
) -> tuple[Optional[list[str]], Optional[dict]]:
    """Parse one LLM turn response.

    Returns:
        ``(files_needed, final_result)`` — exactly one is non-``None`` on
        success; both ``None`` on parse failure.
    """
    text = re.sub(r"^```(?:json)?\s*|```\s*$", "", text.strip(), flags=re.MULTILINE)
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None, None
    if "files_needed" in data and isinstance(data["files_needed"], list):
        return [str(p) for p in data["files_needed"]], None
    if "before_traces" in data:
        return None, data
    return None, None


# ---------------------------------------------------------------------------
# CalltraceExplorer
# ---------------------------------------------------------------------------


class CalltraceExplorer:
    """Orchestrates Git operations + async multi-turn LLM to produce calltraces.

    Args:
        repos_dir:      Local directory where repository clones are stored.
        llm_provider:   LLM provider string (currently only ``"openai"`` is
                        supported via the async client).
        llm_model:      Model name.
        llm_api_key:    API key (or read from env).
        llm_base_url:   Custom base URL (optional).
        clone_via_ssh:  Use SSH (``git@github.com``) instead of HTTPS for
                        cloning.  Requires a loaded SSH key.
        git_proxy:      HTTP/SOCKS proxy forwarded via ``HTTP_PROXY`` /
                        ``HTTPS_PROXY`` to all git sub-processes.
        max_llm_rounds: Maximum LLM conversation turns per CVE (including the
                        first turn with the diff).  Each extra turn lets the
                        model request additional source files to extend the
                        call chain.
    """

    def __init__(
        self,
        repos_dir: str = "./data/repos",
        llm_provider: str = "openai",
        llm_model: str = "deepseek-v3.2",
        llm_api_key: Optional[str] = None,
        llm_base_url: Optional[str] = None,
        clone_via_ssh: bool = False,
        git_proxy: Optional[str] = None,
        max_llm_rounds: int = 4,
    ) -> None:
        self.repos_dir = Path(repos_dir)
        self.clone_via_ssh = clone_via_ssh
        self.git_proxy = git_proxy
        self.max_llm_rounds = max_llm_rounds
        self._model = llm_model
        self._repo_locks: dict[str, asyncio.Lock] = {}
        self._all_stats: list[TokenStats] = []
        self._llm = _AsyncLLMClient(
            model=llm_model,
            api_key=llm_api_key,
            base_url=llm_base_url,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def explore(
        self,
        entry: AVDCveEntry,
        repo_url: str,
        patch_commit: str,
    ) -> tuple[AVDCveEntry, TokenStats]:
        """Enrich *entry* with calltrace data via async multi-turn LLM analysis.

        Git operations on a given repository clone are serialised via a
        per-repository ``asyncio.Lock``; LLM network I/O yields to the event
        loop so other CVEs (on different repos) may progress concurrently.

        Args:
            entry:        The :class:`AVDCveEntry` to enrich (returned with
                          new fields filled in).
            repo_url:     HTTPS clone URL of the repository.
            patch_commit: Full or abbreviated commit SHA of the patch.

        Returns:
            ``(entry, stats)`` — the enriched entry and per-CVE token stats.
            On failure the original entry is returned with zero token counts.
        """
        async with self._get_repo_lock(repo_url):
            try:
                repo_path = await asyncio.to_thread(
                    _clone_or_update,
                    repo_url,
                    self.repos_dir,
                    self.clone_via_ssh,
                    self.git_proxy,
                )
            except Exception as exc:
                logger.error("Failed to clone %s: %s", repo_url, exc)
                return entry, TokenStats(cve_id=entry.CVE)

            diff = await asyncio.to_thread(_get_diff, repo_path, patch_commit)
            if not diff:
                logger.warning("Empty diff for commit %s in %s", patch_commit, repo_url)
                return entry, TokenStats(cve_id=entry.CVE)

            # Checkout vulnerable (pre-patch) version
            parent = await asyncio.to_thread(
                _get_parent_commit, repo_path, patch_commit
            )
            if parent:
                try:
                    await asyncio.to_thread(_checkout, repo_path, parent)
                    entry.vul_version = parent
                except subprocess.CalledProcessError as exc:
                    logger.error("Checkout failed: %s", exc.stderr)

            # Extract patch method names from diff hunk headers
            before_methods, after_methods = _extract_patch_methods(diff, repo_path)
            entry.patch_method_before = before_methods
            entry.patch_method_after = after_methods

            # Checkout patch commit to read post-patch file contents
            patched_files = _parse_diff_files(diff)
            try:
                await asyncio.to_thread(_checkout, repo_path, patch_commit)
            except subprocess.CalledProcessError:
                pass

            initial_files = {
                f: _file_content(repo_path, f)
                for f in patched_files
                if f.endswith(
                    (".java", ".py", ".js", ".ts", ".go", ".php", ".rb", ".kt", ".cs")
                )
            }

            # Multi-turn LLM exploration.  The repo lock is held throughout so
            # the model can request and receive file contents from the checked-
            # out working tree across turns.
            raw_calltrace, stats = await self._ask_llm_multiturn(
                entry, diff, repo_path, initial_files, max_rounds=self.max_llm_rounds
            )
            if raw_calltrace:
                entry = self._merge_calltrace(entry, raw_calltrace)

            # Leave HEAD at patch commit
            try:
                await asyncio.to_thread(_checkout, repo_path, patch_commit)
            except subprocess.CalledProcessError:
                pass

        return entry, stats

    def explore_sync(
        self,
        entry: AVDCveEntry,
        repo_url: str,
        patch_commit: str,
    ) -> tuple[AVDCveEntry, TokenStats]:
        """Synchronous wrapper around :meth:`explore` for non-async callers.

        Appends the resulting :class:`TokenStats` to :attr:`all_stats`.
        """
        result, stats = asyncio.run(self.explore(entry, repo_url, patch_commit))
        self._all_stats.append(stats)
        return result, stats

    async def explore_many(
        self,
        targets: list[tuple[AVDCveEntry, str, str]],
        concurrency: int = 5,
        on_done: Optional[Callable[[AVDCveEntry, "TokenStats"], None]] = None,
    ) -> list[AVDCveEntry]:
        """Process multiple ``(entry, repo_url, patch_commit)`` tuples concurrently.

        Args:
            targets:     List of ``(entry, repo_url, patch_commit)`` tuples.
            concurrency: Maximum simultaneous explorations across all repos.
                         CVEs sharing a repo are always serialised regardless.
            on_done:     Optional callback ``(entry, stats)`` called on the
                         event-loop thread after each CVE is enriched.

        Returns:
            Enriched entries in the same order as *targets*.  On per-entry
            failure the original (unenriched) entry is returned.
        """
        sem = asyncio.Semaphore(concurrency)

        async def _one(entry: AVDCveEntry, repo_url: str, commit: str) -> AVDCveEntry:
            async with sem:
                result, stats = await self.explore(entry, repo_url, commit)
                self._all_stats.append(stats)
                if on_done is not None:
                    on_done(result, stats)
                return result

        tasks = [asyncio.create_task(_one(e, u, c)) for e, u, c in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        out: list[AVDCveEntry] = []
        for i, r in enumerate(results):
            if isinstance(r, BaseException):
                logger.error("explore failed for %s: %s", targets[i][0].CVE, r)
                out.append(targets[i][0])
            else:
                out.append(r)  # type: ignore[arg-type]
        return out

    # ------------------------------------------------------------------
    # Token-stats accessors
    # ------------------------------------------------------------------

    @property
    def all_stats(self) -> list[TokenStats]:
        """Per-CVE token statistics accumulated since this explorer was created."""
        return list(self._all_stats)

    def total_stats(self) -> TokenStats:
        """Return a single :class:`TokenStats` summing all CVEs processed so far."""
        from functools import reduce

        if not self._all_stats:
            return TokenStats(cve_id="total")
        return reduce(lambda a, b: a + b, self._all_stats)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_repo_lock(self, repo_url: str) -> asyncio.Lock:
        """Return a per-repo ``asyncio.Lock`` (created lazily on first access)."""
        key = repo_url.rstrip("/").lower()
        if key not in self._repo_locks:
            self._repo_locks[key] = asyncio.Lock()
        return self._repo_locks[key]

    async def _ask_llm_multiturn(
        self,
        entry: AVDCveEntry,
        diff: str,
        repo_path: Path,
        initial_files: dict[str, str],
        max_rounds: int = 4,
    ) -> tuple[Optional[dict], TokenStats]:
        """Run a multi-turn LLM conversation to produce the calltrace.

        The model may respond with ``{"files_needed": [...]}`` to request
        additional source files each round before providing its final answer.

        Returns ``(final_result, stats)``.
        """
        messages: list[dict[str, str]] = [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": _build_user_prompt(entry, diff, initial_files)},
        ]
        final_result: Optional[dict] = None
        stats = TokenStats(cve_id=entry.CVE)

        for round_num in range(max_rounds):
            is_last = round_num == max_rounds - 1
            try:
                response_text, p_tok, c_tok = await self._llm.chat(messages)
            except Exception as exc:
                logger.error(
                    "[%s] LLM call failed (round %d): %s", entry.CVE, round_num + 1, exc
                )
                break

            stats.rounds += 1
            stats.prompt_tokens += p_tok
            stats.completion_tokens += c_tok

            if not response_text:
                break

            messages.append({"role": "assistant", "content": response_text})
            files_needed, parsed = _parse_llm_response(response_text)

            if parsed is not None:
                final_result = parsed
                logger.debug(
                    "[%s] Calltrace finalised in %d round(s)", entry.CVE, round_num + 1
                )
                break

            if files_needed is None:
                logger.warning(
                    "[%s] Unparseable LLM response (round %d):\n%s",
                    entry.CVE,
                    round_num + 1,
                    response_text[:300],
                )
                break

            # --- model requested more files ---
            if is_last:
                # Force a final answer on the last allowed round
                messages.append(
                    {
                        "role": "user",
                        "content": (
                            "You have reached the maximum number of file requests.  "
                            "Please produce the final JSON calltrace now using the "
                            "context you already have."
                        ),
                    }
                )
                try:
                    response_text, p_tok, c_tok = await self._llm.chat(messages)
                    stats.rounds += 1
                    stats.prompt_tokens += p_tok
                    stats.completion_tokens += c_tok
                    if response_text:
                        _, final_result = _parse_llm_response(response_text)
                except Exception as exc:
                    logger.error("[%s] LLM final-round call failed: %s", entry.CVE, exc)
                break

            # Read the requested files and provide them in the next turn
            loaded: dict[str, str] = {}
            for fpath in files_needed[:10]:  # cap at 10 files per round
                content = _file_content(repo_path, fpath)
                loaded[fpath] = (
                    content if content else f"# File not found in repo: {fpath}"
                )

            followup_content = (
                "\n\n".join(
                    f"### FILE: {path}\n```\n{content[:6000]}\n```"
                    for path, content in loaded.items()
                )
                or "No additional files could be found for the paths you requested."
            )
            messages.append({"role": "user", "content": followup_content})
            logger.debug(
                "[%s] Round %d: provided %d requested file(s)",
                entry.CVE,
                round_num + 1,
                len(loaded),
            )

        return final_result, stats

    def _merge_calltrace(self, entry: AVDCveEntry, data: dict) -> AVDCveEntry:
        """Merge parsed LLM output into *entry*."""

        def _frames(raw_list: list) -> list[list[TraceFrame]]:
            traces: list[list[TraceFrame]] = []
            for chain in raw_list:
                if not isinstance(chain, list):
                    chain = [chain]
                frames: list[TraceFrame] = []
                for f in chain:
                    if isinstance(f, dict):
                        try:
                            frames.append(
                                TraceFrame(
                                    depth=int(f.get("depth", 0)),
                                    file=str(f.get("file", "")),
                                    method=str(f.get("method", "")),
                                    start_line=int(f.get("start_line", 0)),
                                    end_line=int(f.get("end_line", 0)),
                                )
                            )
                        except Exception:
                            pass
                if frames:
                    traces.append(frames)
            return traces

        entry.CallTrace = CallTraceData(
            before_traces=_frames(data.get("before_traces", [])),
            after_traces=_frames(data.get("after_traces", [])),
        )
        if data.get("source"):
            entry.source = [str(s) for s in data["source"]]
        if data.get("sink"):
            entry.sink = [str(s) for s in data["sink"]]
        if data.get("reason"):
            entry.reason = str(data["reason"])

        return entry
