"""Compatibility wrapper around the configured LLM transport."""

from typing import Any

from codegraph.llm.transport.base import LLMRequest
from codegraph.llm.transport.litellm_transport import LiteLLMTransport


_DEFAULT_TRANSPORT = LiteLLMTransport()


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
    return _DEFAULT_TRANSPORT.generate(request)
