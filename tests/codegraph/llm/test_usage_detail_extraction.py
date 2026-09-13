"""Usage detail extraction must match the provider SDK's own field names.

The chat-completions and responses shapes name their detail containers
differently, and a locally served model reports neither. Guessing a container
name silently yields zero cached units, which inflates a reported cost rather
than failing visibly.
"""

from __future__ import annotations

import pytest

from codegraph.llm.transport.openai_compatible_transport import _usage_detail_counts

CHAT_NAMES = {"prompt": "prompt_tokens", "completion": "completion_tokens", "total": "total_tokens"}
RESPONSES_NAMES = {"prompt": "input_tokens", "completion": "output_tokens", "total": ""}


class _Shape:
    def __init__(self, **fields):
        for key, value in fields.items():
            setattr(self, key, value)


def test_chat_completions_shape() -> None:
    usage = _Shape(
        prompt_tokens_details=_Shape(cached_tokens=640),
        completion_tokens_details=_Shape(reasoning_tokens=128),
    )
    assert _usage_detail_counts(usage, CHAT_NAMES) == (640, 128)


def test_responses_shape() -> None:
    usage = _Shape(
        input_tokens_details=_Shape(cached_tokens=32),
        output_tokens_details=_Shape(reasoning_tokens=8),
    )
    assert _usage_detail_counts(usage, RESPONSES_NAMES) == (32, 8)


def test_provider_without_detail_containers_reports_zero() -> None:
    """A locally served model has no detail containers; zero is correct, not an error."""
    assert _usage_detail_counts(_Shape(prompt_tokens=10, completion_tokens=2), CHAT_NAMES) == (0, 0)


def test_absent_usage_is_zero() -> None:
    assert _usage_detail_counts(None, CHAT_NAMES) == (0, 0)


@pytest.mark.parametrize("value", [None, -1, 0, "not-a-number"])
def test_malformed_or_non_positive_values_are_zero(value) -> None:
    usage = _Shape(prompt_tokens_details=_Shape(cached_tokens=value))
    assert _usage_detail_counts(usage, CHAT_NAMES)[0] == 0


if __name__ == "__main__":
    pytest.main([__file__])
