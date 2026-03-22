from __future__ import annotations

import dataclasses


@dataclasses.dataclass
class TokenUsage:
    rounds: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0

    def __add__(self, other: "TokenUsage") -> "TokenUsage":
        return TokenUsage(
            rounds=self.rounds + other.rounds,
            prompt_tokens=self.prompt_tokens + other.prompt_tokens,
            completion_tokens=self.completion_tokens + other.completion_tokens,
        )
