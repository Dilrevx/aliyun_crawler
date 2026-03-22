from __future__ import annotations

import json
import logging
import re
from typing import Any, Optional

from aliyun_crawler.agents.contracts import TokenUsage
from aliyun_crawler.models import AVDCveEntry, PatchMethod

logger = logging.getLogger(__name__)

_VALIDATOR_SYSTEM_PROMPT = """\
You are a strict calltrace validator.

Task:
1) Validate candidate before/after traces.
2) Ensure direction is correct: depth 0 is HTTP/RPC entry, deepest is patched method.
3) Ensure patched methods are represented in the deepest relevant frame(s).
4) Drop unsupported frames and keep only repository-relative file paths.
5) Return FINAL JSON only in this schema:
{
    "before_traces": [[{"depth":0,"file":"...","method":"...","start_line":0,"end_line":0}]],
    "after_traces": [[{"depth":0,"file":"...","method":"...","start_line":0,"end_line":0}]],
    "source": ["..."],
    "sink": ["..."],
    "reason": "..."
}

Rules:
- No markdown, no prose outside JSON.
- Use 0 for unknown line numbers.
"""


def _build_validator_user_prompt(
    entry: AVDCveEntry,
    diff: str,
    candidate_result: dict,
    patch_before: list[PatchMethod],
    patch_after: list[PatchMethod],
) -> str:
    hint_before = [m.model_dump() for m in patch_before]
    hint_after = [m.model_dump() for m in patch_after]
    return f"""\
CVE: {entry.CVE}

## Patch diff (for grounding)
```diff
{diff[:5000]}
```

## Patch methods before
{json.dumps(hint_before, ensure_ascii=False)}

## Patch methods after
{json.dumps(hint_after, ensure_ascii=False)}

## Explorer candidate
{json.dumps(candidate_result, ensure_ascii=False)}

Note:
- Patch methods above are heuristic hints extracted from diff hunk headers and may be noisy.
- Prefer raw diff and candidate traces as primary evidence.

Validate and return the final JSON in required schema.
"""


def _parse_llm_response(text: str) -> Optional[dict]:
    text = re.sub(r"^```(?:json)?\s*|```\s*$", "", text.strip(), flags=re.MULTILINE)
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return None
    if "before_traces" in data:
        return data
    return None


class EvaluatorAgent:
    def __init__(self, llm_client: Any) -> None:
        self._llm = llm_client

    async def run(
        self,
        entry: AVDCveEntry,
        diff: str,
        candidate_result: dict,
        patch_before: list[PatchMethod],
        patch_after: list[PatchMethod],
    ) -> tuple[Optional[dict], TokenUsage]:
        messages: list[dict[str, str]] = [
            {"role": "system", "content": _VALIDATOR_SYSTEM_PROMPT},
            {
                "role": "user",
                "content": _build_validator_user_prompt(
                    entry,
                    diff,
                    candidate_result,
                    patch_before,
                    patch_after,
                ),
            },
        ]

        usage = TokenUsage()
        try:
            response_text, p_tok, c_tok = await self._llm.chat(messages)
        except Exception as exc:
            logger.error("[%s] Evaluator LLM call failed: %s", entry.CVE, exc)
            return None, usage

        usage.rounds = 1
        usage.prompt_tokens = p_tok
        usage.completion_tokens = c_tok

        if not response_text:
            return None, usage

        return _parse_llm_response(response_text), usage
