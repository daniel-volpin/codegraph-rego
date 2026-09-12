from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol


@dataclass(frozen=True)
class LLMRequest:
    messages: Sequence[Mapping[str, str]]
    model: str | None = None
    temperature: float | None = None
    max_tokens: int | None = None
    ttl_seconds: int | None = None
    stop: list[str] | str | None = None
    response_format: dict[str, Any] | None = None
    tools: Sequence[Mapping[str, Any]] | None = None
    raise_on_error: bool = False


class LLMTransport(Protocol):
    def generate(self, request: LLMRequest) -> str: ...


class LLMUnavailableError(RuntimeError):
    """Raised when an LLM request fails and the caller wants to handle it explicitly."""
