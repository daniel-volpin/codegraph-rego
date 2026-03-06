"""
Wrapper around LiteLLM to support multiple LLM providers (OpenAI, LM Studio, etc.).

Configuration is controlled via environment variables (see config.py):

- LLM_PROVIDER: provider name understood by LiteLLM (default: "openai").
- LLM_MODEL: model identifier to request (default: "gpt-4o-mini").
- LLM_API_KEY: API key/token (optional for local providers like LM Studio).
- LLM_API_BASE: Custom base URL (e.g., http://localhost:1234/v1 for LM Studio).
- LLM_TEMPERATURE: Optional float, default 0.2.
- LLM_ENABLE_THINKING: Optional bool, default true. Set to false to disable
  chain-of-thought <think> blocks on models that support it (e.g. Qwen3, DeepSeek).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from codegraph.config import (
    LLM_PROVIDER,
    LLM_MODEL,
    LLM_API_BASE,
    LLM_API_KEY,
    LLM_TEMPERATURE,
    LLM_ENABLE_THINKING,
    LLM_MAX_TOKENS_EXPLANATION,
)

try:
    import litellm  # type: ignore
except Exception:  # pragma: no cover - allows graceful fallback when dependency missing
    litellm = None  # type: ignore


logger = logging.getLogger("codegraph.llm.client")


class LLMUnavailableError(RuntimeError):
    """Raised when an LLM request fails and the caller wants to handle it explicitly."""


def _summarize_exception(exc: Exception) -> str:
    msg = str(exc).strip() or exc.__class__.__name__
    # LiteLLM/OpenAI exceptions often embed a full traceback in the exception string.
    if "Traceback" in msg:
        msg = msg.split("Traceback", 1)[0].strip(" :-\n\t")
    if len(msg) > 300:
        msg = msg[:300].rstrip() + "…"
    return msg


def _humanize_llm_failure(exc: Exception) -> str:
    summary = _summarize_exception(exc)
    lowered = summary.lower()

    if "connection refused" in lowered or "connecterror" in lowered:
        if LLM_API_BASE:
            return f"LLM server is unreachable (connection refused). Is it running at {LLM_API_BASE}?"
        return "LLM server is unreachable (connection refused). If you're using LM Studio, start the server and set LLM_API_BASE (e.g. http://localhost:1234/v1)."

    if "timed out" in lowered or "timeout" in lowered:
        return "LLM request timed out. Check that your LLM server is running and responsive."

    if "api key" in lowered or "authentication" in lowered or "unauthorized" in lowered:
        return "LLM authentication failed. Check LLM_API_KEY and provider configuration."

    return f"LLM request failed: {summary}"


def generate_chat_completion(
    messages: List[Dict[str, str]],
    *,
    model: Optional[str] = None,
    temperature: Optional[float] = None,
    max_tokens: Optional[int] = None,
    response_format: Optional[Dict[str, Any]] = None,
    raise_on_error: bool = False,
) -> str:
    """Generate a chat completion via LiteLLM.

    Returns the response text, or a fallback string describing why generation failed.
    """

    if litellm is None:
        message = "LLM support is unavailable (litellm not installed)."
        if raise_on_error:
            raise LLMUnavailableError(message)
        return f"[LLM unavailable: {message}]"

    provider = (LLM_PROVIDER or "openai").strip().lower()
    params = {
        "model": (model or LLM_MODEL or "gpt-4o-mini"),
        "messages": messages,
        "temperature": temperature if temperature is not None else LLM_TEMPERATURE,
    }
    # If caller didn't supply a limit, we default to the explanation cap as a generic safe limit.
    # Remediation specifically overrides this when calling generate_chat_completion.
    effective_max_tokens = max_tokens if max_tokens is not None else LLM_MAX_TOKENS_EXPLANATION
    if effective_max_tokens is not None:
        params["max_tokens"] = effective_max_tokens
    if response_format is not None:
        params["response_format"] = response_format
    if LLM_API_KEY:
        params["api_key"] = LLM_API_KEY
    if LLM_API_BASE:
        params["api_base"] = LLM_API_BASE
    if provider:
        params["custom_llm_provider"] = provider

    # Pass enable_thinking to the model via extra_body.
    # Set LLM_ENABLE_THINKING=false in .env to suppress <think> blocks
    # on models that support it (Qwen3, DeepSeek, etc.).
    if not LLM_ENABLE_THINKING:
        params["extra_body"] = {
            "enable_thinking": False,
            "chat_template_kwargs": {"enable_thinking": False},
        }

    try:
        response = litellm.completion(**params)  # type: ignore[arg-type]
        choices = response.get("choices") if isinstance(response, dict) else getattr(response, "choices", None)
        if not choices:
            message = "LLM returned an empty response."
            if raise_on_error:
                raise LLMUnavailableError(message)
            return f"[LLM unavailable: {message}]"
        message = choices[0].get("message") if isinstance(choices[0], dict) else getattr(choices[0], "message", None)
        content = message.get("content") if isinstance(message, dict) else getattr(message, "content", "")
        return (content or "").strip()
    except Exception as exc:  # pragma: no cover - runtime guard
        logger.exception("LLM completion failed (provider=%s model=%s api_base=%s)", provider, params.get("model"), LLM_API_BASE)
        message = _humanize_llm_failure(exc)
        if raise_on_error:
            raise LLMUnavailableError(message) from exc
        return f"[LLM unavailable: {message}]"
