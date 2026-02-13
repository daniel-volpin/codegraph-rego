"""
Wrapper around LiteLLM to support multiple LLM providers (OpenAI, LM Studio, etc.).

Configuration is controlled via environment variables (see config.py):

- LLM_PROVIDER: provider name understood by LiteLLM (default: "openai").
- LLM_MODEL: model identifier to request (default: "gpt-4o-mini").
- LLM_API_KEY: API key/token (optional for local providers like LM Studio).
- LLM_API_BASE: Custom base URL (e.g., http://localhost:1234/v1 for LM Studio).
- LLM_TEMPERATURE: Optional float, default 0.2.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from codegraph.config import (
    LLM_PROVIDER,
    LLM_MODEL,
    LLM_API_BASE,
    LLM_API_KEY,
    LLM_TEMPERATURE,
)

try:
    import litellm  # type: ignore
except Exception:  # pragma: no cover - allows graceful fallback when dependency missing
    litellm = None  # type: ignore


def generate_chat_completion(
    messages: List[Dict[str, str]],
    *,
    model: Optional[str] = None,
    temperature: Optional[float] = None,
    max_tokens: Optional[int] = None,
    response_format: Optional[Dict[str, Any]] = None,
) -> str:
    """Generate a chat completion via LiteLLM.

    Returns the response text, or a fallback string describing why generation failed.
    """

    if litellm is None:
        return "[LLM unavailable: litellm not installed]"

    provider = (LLM_PROVIDER or "openai").strip().lower()
    params = {
        "model": (model or LLM_MODEL or "gpt-4o-mini"),
        "messages": messages,
        "temperature": temperature if temperature is not None else LLM_TEMPERATURE,
    }
    if max_tokens is not None:
        params["max_tokens"] = max_tokens
    if response_format is not None:
        params["response_format"] = response_format
    if LLM_API_KEY:
        params["api_key"] = LLM_API_KEY
    if LLM_API_BASE:
        params["api_base"] = LLM_API_BASE
    if provider:
        params["custom_llm_provider"] = provider

    try:
        response = litellm.completion(**params)  # type: ignore[arg-type]
        choices = response.get("choices") if isinstance(response, dict) else getattr(response, "choices", None)
        if not choices:
            return "[LLM unavailable or failed: empty response]"
        message = choices[0].get("message") if isinstance(choices[0], dict) else getattr(choices[0], "message", None)
        content = message.get("content") if isinstance(message, dict) else getattr(message, "content", "")
        return (content or "").strip()
    except Exception as exc:  # pragma: no cover - runtime guard
        return f"[LLM unavailable or failed: {exc}]"
