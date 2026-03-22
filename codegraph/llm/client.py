"""Compatibility wrapper around the configured LLM transport."""

from typing import Any

from codegraph.llm.transport.base import LLMRequest, LLMUnavailableError
from codegraph.llm.transport.openai_compatible_transport import OpenAICompatibleTransport


__all__ = ["generate_chat_completion", "LLMUnavailableError"]


_DEFAULT_TRANSPORT = OpenAICompatibleTransport()


def generate_chat_completion(
    messages: list[dict[str, str]],
    *,
    model: str | None = None,
    temperature: float | None = None,
    max_tokens: int | None = None,
    ttl_seconds: int | None = None,
    stop: list[str] | str | None = None,
    response_format: dict[str, Any] | None = None,
    raise_on_error: bool = False,
    task_type: str = "",
    retry_index: int = 0,
) -> str:
    """Generate a chat completion via the default transport."""

    request = LLMRequest(
        messages=messages,
        model=model,
        temperature=temperature,
        max_tokens=max_tokens,
        ttl_seconds=ttl_seconds,
        stop=stop,
        response_format=response_format,
        raise_on_error=raise_on_error,
    )
    return _DEFAULT_TRANSPORT.generate(request, task_type=task_type, retry_index=retry_index)
