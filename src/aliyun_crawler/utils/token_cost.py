"""Token cost estimation utilities.

Shared by ``scripts/token_cost.py`` (offline pre-flight estimates) and
``dev_run.py`` / the LLM analyzer (live post-run reporting).
"""

from __future__ import annotations

from typing import Callable, Optional

# ---------------------------------------------------------------------------
# Pricing table: model -> (input $/1M tokens, output $/1M tokens)
# Prices as of early 2026.
# ---------------------------------------------------------------------------
MODEL_PRICING: dict[str, tuple[float, float]] = {
    # GPT-4.1 family
    "gpt-4.1": (2.00, 8.00),
    "gpt-4.1-mini": (0.40, 1.60),
    "gpt-4.1-nano": (0.10, 0.40),
    # GPT-5 family
    "gpt-5": (1.25, 10.00),
    "gpt-5-mini": (0.25, 2.00),
    # GPT-4o family
    "gpt-4o": (2.50, 10.00),
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4o-2024-11-20": (2.50, 10.00),
    "gpt-4o-2024-08-06": (2.50, 10.00),
    "gpt-4o-mini-2024-07-18": (0.15, 0.60),
    # o-series
    "o1": (15.00, 60.00),
    "o1-mini": (3.00, 12.00),
    "o3": (2.00, 8.00),
    "o3-mini": (1.10, 4.40),
    "o4-mini": (1.10, 4.40),
    # Claude 3.5 / 3
    "claude-3-5-sonnet": (3.00, 15.00),
    "claude-3-5-haiku": (1.00, 5.00),
    "claude-3-opus": (15.00, 75.00),
    "claude-3-sonnet": (3.00, 15.00),
    "claude-3-haiku": (1.00, 5.00),
    # Claude 4
    "claude-sonnet-4-6": (3.00, 15.00),
    "claude-haiku-4-5": (1.00, 5.00),
    # Gemini
    "gemini-2.0-flash": (0.60, 2.40),
    "gemini-1.5-pro": (2.50, 10.00),
    "gemini-1.5-flash": (1.50, 6.00),
}

FALLBACK_MODEL = "gpt-5-mini"


def resolve_pricing(
    model: str,
    warn_fn: Optional[Callable[[str], None]] = None,
) -> tuple[float, float]:
    """Return ``(input_price, output_price)`` per 1M tokens for *model*.

    Lookup order:
    1. Exact match in ``MODEL_PRICING``.
    2. Longest prefix/substring match (e.g. ``gpt-4o-mini-2024`` → ``gpt-4o-mini``).
    3. Fallback to ``FALLBACK_MODEL`` pricing.

    Args:
        model:   LLM model identifier string.
        warn_fn: Optional callable that receives a human-readable warning
                 message when an exact match is not found.  Pass
                 ``print`` or ``console.print`` from the call site.
    """
    if model in MODEL_PRICING:
        return MODEL_PRICING[model]

    candidates = [
        (k, v)
        for k, v in MODEL_PRICING.items()
        if model.startswith(k) or k.startswith(model)
    ]
    if candidates:
        best_key, best_price = max(candidates, key=lambda x: len(x[0]))
        if warn_fn:
            warn_fn(f"Unknown model '{model}', matched pricing for '{best_key}'.")
        return best_price

    if warn_fn:
        warn_fn(f"Unknown model '{model}', falling back to {FALLBACK_MODEL} pricing.")
    return MODEL_PRICING[FALLBACK_MODEL]


def estimate_cost(
    prompt_tokens: int,
    completion_tokens: int,
    model: str,
    warn_fn: Optional[Callable[[str], None]] = None,
) -> float:
    """Return estimated dollar cost for *prompt_tokens* + *completion_tokens*.

    Args:
        prompt_tokens:     Number of input/prompt tokens consumed.
        completion_tokens: Number of output/completion tokens generated.
        model:             LLM model identifier; used to look up pricing.
        warn_fn:           Forwarded to :func:`resolve_pricing`.
    """
    input_price_1M, output_price_1M = resolve_pricing(model, warn_fn=warn_fn)
    return (
        prompt_tokens / 1_000_000 * input_price_1M
        + completion_tokens / 1_000_000 * output_price_1M
    )
