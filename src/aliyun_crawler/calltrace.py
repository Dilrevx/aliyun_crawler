"""LLM-driven calltrace exploration (v2 only).

This module keeps the public `CalltraceExplorer` API stable while delegating
actual exploration/evaluation logic to the v2 multi-agent stack:
Coordinator + Explorer + Evaluator.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any, Optional

from aliyun_crawler.agents.contracts import TokenUsage
from aliyun_crawler.agents.coordinator import CalltraceCoordinator
from aliyun_crawler.agents.tools import RepositoryTools, SummaryTool
from aliyun_crawler.models import AVDCveEntry, CallTraceData, PatchMethod, TraceFrame

logger = logging.getLogger(__name__)


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
        try:
            from aliyun_crawler.utils.token_cost import estimate_cost

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


# More robust: extract changed line ranges and map to method names by reading
# the file content.
def _extract_patch_methods(
    diff: str, repo_path: Path
) -> tuple[list[PatchMethod], list[PatchMethod]]:
    """Parse a git diff to produce before/after `PatchMethod` lists."""
    del repo_path

    before: list[PatchMethod] = []
    after: list[PatchMethod] = []
    current_file = ""

    for line in diff.splitlines():
        if line.startswith("--- a/"):
            current_file = line[6:]
        elif line.startswith("+++ b/"):
            current_file = line[6:]
        elif line.startswith("@@"):
            hunk_m = re.match(r"@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@\s*(.*)", line)
            if not hunk_m:
                continue

            before_start = int(hunk_m.group(1))
            after_start = int(hunk_m.group(2))
            method_hint = hunk_m.group(3).strip()

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
                        end_line=before_start,
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

    def _dedup(methods: list[PatchMethod]) -> list[PatchMethod]:
        seen: set[tuple[str, str]] = set()
        out: list[PatchMethod] = []
        for item in methods:
            key = (item.file, item.method)
            if key not in seen:
                seen.add(key)
                out.append(item)
        return out

    return _dedup(before), _dedup(after)


class CalltraceExplorer:
    """Public façade for calltrace generation using v2 coordinator workflow."""

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
        del llm_provider

        self.repos_dir = Path(repos_dir)
        self.max_llm_rounds = max_llm_rounds
        self._model = llm_model
        self._repo_locks: dict[str, asyncio.Lock] = {}
        self._all_stats: list[TokenStats] = []

        self._tools = RepositoryTools(
            clone_via_ssh=clone_via_ssh,
            git_proxy=git_proxy,
        )
        self._summary_tool = SummaryTool()
        self._llm = _AsyncLLMClient(
            model=llm_model,
            api_key=llm_api_key,
            base_url=llm_base_url,
        )
        self._coordinator = CalltraceCoordinator(
            tools=self._tools,
            summary_tool=self._summary_tool,
            llm_client=self._llm,
            max_llm_rounds=max_llm_rounds,
        )

    async def explore(
        self,
        entry: AVDCveEntry,
        repo_url: str,
        patch_commit: str,
    ) -> tuple[AVDCveEntry, TokenStats]:
        usage = TokenUsage()
        async with self._get_repo_lock(repo_url):
            entry, usage = await self._coordinator.run(
                entry=entry,
                repo_url=repo_url,
                patch_commit=patch_commit,
                repos_dir=self.repos_dir,
                extract_patch_methods=_extract_patch_methods,
                append_skip_reason=self._append_skip_reason,
                trace_contains_patch_method=self._trace_contains_patch_method,
                merge_calltrace=self._merge_calltrace,
            )

        return (
            entry,
            TokenStats(
                cve_id=entry.CVE,
                rounds=usage.rounds,
                prompt_tokens=usage.prompt_tokens,
                completion_tokens=usage.completion_tokens,
            ),
        )

    def explore_sync(
        self,
        entry: AVDCveEntry,
        repo_url: str,
        patch_commit: str,
    ) -> tuple[AVDCveEntry, TokenStats]:
        result, stats = asyncio.run(self.explore(entry, repo_url, patch_commit))
        self._all_stats.append(stats)
        return result, stats

    async def explore_many(
        self,
        targets: list[tuple[AVDCveEntry, str, str]],
        concurrency: int = 5,
        on_done: Optional[Callable[[AVDCveEntry, TokenStats], None]] = None,
    ) -> list[AVDCveEntry]:
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
        for i, result in enumerate(results):
            if isinstance(result, BaseException):
                logger.error("explore failed for %s: %s", targets[i][0].CVE, result)
                out.append(targets[i][0])
            else:
                out.append(result)  # type: ignore[arg-type]
        return out

    @property
    def all_stats(self) -> list[TokenStats]:
        return list(self._all_stats)

    def total_stats(self) -> TokenStats:
        from functools import reduce

        if not self._all_stats:
            return TokenStats(cve_id="total")
        return reduce(lambda a, b: a + b, self._all_stats)

    def _get_repo_lock(self, repo_url: str) -> asyncio.Lock:
        key = repo_url.rstrip("/").lower()
        if key not in self._repo_locks:
            self._repo_locks[key] = asyncio.Lock()
        return self._repo_locks[key]

    @staticmethod
    def _append_skip_reason(entry: AVDCveEntry, message: str) -> None:
        base = (entry.reason or "").strip()
        marker = f"[calltrace skipped] {message}"
        entry.reason = marker if not base else f"{base}\n{marker}"

    @staticmethod
    def _trace_contains_patch_method(
        calltrace_result: dict,
        patch_methods: list[PatchMethod],
    ) -> bool:
        if not patch_methods:
            return False
        patch_keys = {(p.file, p.method) for p in patch_methods if p.file and p.method}
        if not patch_keys:
            return False

        for trace_key in ("before_traces", "after_traces"):
            traces = calltrace_result.get(trace_key, [])
            if not isinstance(traces, list):
                continue
            for chain in traces:
                if not isinstance(chain, list):
                    continue
                for frame in chain:
                    if not isinstance(frame, dict):
                        continue
                    file_path = str(frame.get("file", ""))
                    method = str(frame.get("method", ""))
                    if (file_path, method) in patch_keys:
                        return True
        return False

    def _merge_calltrace(self, entry: AVDCveEntry, data: dict) -> AVDCveEntry:
        def _frames(raw_list: list) -> list[list[TraceFrame]]:
            traces: list[list[TraceFrame]] = []
            for chain in raw_list:
                if not isinstance(chain, list):
                    chain = [chain]
                frames: list[TraceFrame] = []
                for frame in chain:
                    if isinstance(frame, dict):
                        try:
                            frames.append(
                                TraceFrame(
                                    depth=int(frame.get("depth", 0)),
                                    file=str(frame.get("file", "")),
                                    method=str(frame.get("method", "")),
                                    start_line=int(frame.get("start_line", 0)),
                                    end_line=int(frame.get("end_line", 0)),
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
