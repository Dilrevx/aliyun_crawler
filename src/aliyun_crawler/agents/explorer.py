from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Optional

from aliyun_crawler.agents.contracts import TokenUsage
from aliyun_crawler.agents.tools import RepositoryTools, SummaryTool
from aliyun_crawler.models import AVDCveEntry

logger = logging.getLogger(__name__)

_EXPLORER_SYSTEM_PROMPT = """\
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


def _build_explorer_user_prompt(
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


class ExplorerAgent:
    def __init__(
        self,
        llm_client: Any,
        tools: RepositoryTools,
        summary_tool: SummaryTool,
        max_files_per_round: int = 10,
    ) -> None:
        self._llm = llm_client
        self._tools = tools
        self._summary = summary_tool
        self._max_files_per_round = max_files_per_round

    async def run(
        self,
        entry: AVDCveEntry,
        diff: str,
        repo_path: Path,
        initial_files: dict[str, str],
        max_rounds: int,
    ) -> tuple[Optional[dict], TokenUsage]:
        messages: list[dict[str, str]] = [
            {"role": "system", "content": _EXPLORER_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": _build_explorer_user_prompt(entry, diff, initial_files),
            },
        ]

        usage = TokenUsage()
        final_result: Optional[dict] = None

        for round_num in range(max_rounds):
            is_last = round_num == max_rounds - 1
            try:
                response_text, p_tok, c_tok = await self._llm.chat(messages)
            except Exception as exc:
                logger.error(
                    "[%s] Explorer LLM call failed (round %d): %s",
                    entry.CVE,
                    round_num + 1,
                    exc,
                )
                break

            usage.rounds += 1
            usage.prompt_tokens += p_tok
            usage.completion_tokens += c_tok

            if not response_text:
                break

            messages.append({"role": "assistant", "content": response_text})
            files_needed, parsed = _parse_llm_response(response_text)

            if parsed is not None:
                final_result = parsed
                break

            if files_needed is None:
                logger.warning(
                    "[%s] Unparseable explorer response (round %d): %s",
                    entry.CVE,
                    round_num + 1,
                    response_text[:300],
                )
                break

            if is_last:
                messages.append(
                    {
                        "role": "user",
                        "content": (
                            "You have reached the maximum number of file requests. "
                            "Please produce the final JSON calltrace now using the "
                            "context you already have."
                        ),
                    }
                )
                try:
                    response_text, p_tok, c_tok = await self._llm.chat(messages)
                    usage.rounds += 1
                    usage.prompt_tokens += p_tok
                    usage.completion_tokens += c_tok
                    if response_text:
                        _, final_result = _parse_llm_response(response_text)
                except Exception as exc:
                    logger.error(
                        "[%s] Explorer final-round call failed: %s", entry.CVE, exc
                    )
                break

            loaded: dict[str, str] = {}
            for fpath in files_needed[: self._max_files_per_round]:
                content = self._tools.read_repo_file(repo_path, fpath)
                if not content:
                    loaded[fpath] = f"# File not found in repo: {fpath}"
                    continue
                if len(content) > 6000:
                    loaded[fpath] = self._summary.summarize_file(
                        content, max_lines=120, max_chars=6000
                    )
                else:
                    loaded[fpath] = content

            followup_content = (
                "\n\n".join(
                    f"### FILE: {path}\n```\n{content[:6000]}\n```"
                    for path, content in loaded.items()
                )
                or "No additional files could be found for the paths you requested."
            )
            messages.append({"role": "user", "content": followup_content})

        return final_result, usage
