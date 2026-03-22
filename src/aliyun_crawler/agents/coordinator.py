from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from typing import Callable

from aliyun_crawler.agents.contracts import TokenUsage
from aliyun_crawler.agents.evaluator import EvaluatorAgent
from aliyun_crawler.agents.explorer import ExplorerAgent
from aliyun_crawler.agents.tools import RepositoryTools, SummaryTool
from aliyun_crawler.models import AVDCveEntry, PatchMethod

logger = logging.getLogger(__name__)

_SUPPORTED_SOURCE_SUFFIXES = (
    ".java",
    ".py",
    ".js",
    ".ts",
    ".go",
    ".php",
    ".rb",
    ".kt",
    ".cs",
)


class CalltraceCoordinator:
    def __init__(
        self,
        tools: RepositoryTools,
        summary_tool: SummaryTool,
        llm_client: object,
        max_llm_rounds: int,
    ) -> None:
        self._tools = tools
        self._summary = summary_tool
        self._max_llm_rounds = max_llm_rounds
        self._explorer = ExplorerAgent(
            llm_client=llm_client, tools=tools, summary_tool=summary_tool
        )
        self._evaluator = EvaluatorAgent(llm_client=llm_client)

    async def run(
        self,
        entry: AVDCveEntry,
        repo_url: str,
        patch_commit: str,
        repos_dir: Path,
        extract_patch_methods: Callable[
            [str, Path], tuple[list[PatchMethod], list[PatchMethod]]
        ],
        append_skip_reason: Callable[[AVDCveEntry, str], None],
        trace_contains_patch_method: Callable[[dict, list[PatchMethod]], bool],
        merge_calltrace: Callable[[AVDCveEntry, dict], AVDCveEntry],
    ) -> tuple[AVDCveEntry, TokenUsage]:
        try:
            repo_path = self._tools.clone_or_update(repo_url, repos_dir)
        except Exception as exc:
            logger.error("Failed to clone %s: %s", repo_url, exc)
            return entry, TokenUsage()

        diff = self._tools.get_diff(repo_path, patch_commit)
        if not diff:
            logger.warning("Empty diff for commit %s in %s", patch_commit, repo_url)
            return entry, TokenUsage()

        parent = self._tools.get_parent_commit(repo_path, patch_commit)
        if parent:
            try:
                self._tools.checkout(repo_path, parent)
                entry.vul_version = parent
            except subprocess.CalledProcessError as exc:
                logger.error("Checkout failed: %s", exc.stderr)

        before_methods, after_methods = extract_patch_methods(diff, repo_path)
        entry.patch_method_before = before_methods
        entry.patch_method_after = after_methods

        if not before_methods and not after_methods:
            logger.warning(
                "[%s] No patch methods detected from diff hunks; continuing with raw diff only",
                entry.CVE,
            )

        patched_files = self._tools.parse_diff_files(diff)
        if not patched_files:
            msg = "No patched files detected from diff"
            logger.error("[%s] %s; skipping", entry.CVE, msg)
            append_skip_reason(entry, msg)
            return entry, TokenUsage()

        try:
            self._tools.checkout(repo_path, patch_commit)
        except subprocess.CalledProcessError:
            pass

        initial_files = {
            path: self._tools.read_repo_file(repo_path, path)
            for path in patched_files
            if path.endswith(_SUPPORTED_SOURCE_SUFFIXES)
        }

        if not initial_files:
            msg = "Patched files contain no supported source file types"
            logger.error("[%s] %s; skipping", entry.CVE, msg)
            append_skip_reason(entry, msg)
            return entry, TokenUsage()

        raw_calltrace, explorer_usage = await self._explorer.run(
            entry=entry,
            diff=diff,
            repo_path=repo_path,
            initial_files=initial_files,
            max_rounds=self._max_llm_rounds,
        )

        usage = explorer_usage
        if raw_calltrace:
            validated_calltrace, evaluator_usage = await self._evaluator.run(
                entry=entry,
                diff=diff,
                candidate_result=raw_calltrace,
                patch_before=before_methods,
                patch_after=after_methods,
            )
            usage = usage + evaluator_usage

            final_calltrace = validated_calltrace or raw_calltrace
            if before_methods or after_methods:
                if not trace_contains_patch_method(
                    final_calltrace, before_methods + after_methods
                ):
                    logger.warning(
                        "[%s] Evaluator result does not include heuristic patch methods; accepting trace",
                        entry.CVE,
                    )
                    append_skip_reason(
                        entry,
                        "evaluator output does not include heuristic patch-method hints",
                    )

            entry = merge_calltrace(entry, final_calltrace)

        try:
            self._tools.checkout(repo_path, patch_commit)
        except subprocess.CalledProcessError:
            pass

        return entry, usage
