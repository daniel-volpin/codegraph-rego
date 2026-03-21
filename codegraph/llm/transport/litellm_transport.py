from __future__ import annotations

import logging
from typing import Any

from codegraph.config import settings
from codegraph.llm.transport.base import LLMRequest, LLMTransport, LLMUnavailableError

try:
    import litellm  # type: ignore
except Exception:  # pragma: no cover - allows graceful fallback when dependency missing
    litellm = None  # type: ignore


logger = logging.getLogger("codegraph.llm.transport.litellm")


def _summarize_exception(exc: Exception) -> str:
    msg = str(exc).strip() or exc.__class__.__name__
    if "Traceback" in msg:
        msg = msg.split("Traceback", 1)[0].strip(" :-\n\t")
    if len(msg) > 300:
        msg = msg[:300].rstrip() + "…"
    return msg


def _humanize_llm_failure(exc: Exception, *, api_base: str | None) -> str:
    summary = _summarize_exception(exc)
    lowered = summary.lower()

    if "connection refused" in lowered or "connecterror" in lowered:
        if api_base:
            return f"LLM server is unreachable (connection refused). Is it running at {api_base}?"
        return (
            "LLM server is unreachable (connection refused). If you're using LM Studio, "
            "start the server and set LLM_API_BASE (e.g. http://localhost:1234/v1)."
        )

    if "timed out" in lowered or "timeout" in lowered:
        return "LLM request timed out. Check that your LLM server is running and responsive."

    if "api key" in lowered or "authentication" in lowered or "unauthorized" in lowered:
        return "LLM authentication failed. Check LLM_API_KEY and provider configuration."

    return f"LLM request failed: {summary}"


def _is_lm_studio_api_base(api_base: str | None) -> bool:
    if not api_base:
        return False
    lowered = api_base.lower()
    return "localhost:1234" in lowered or "127.0.0.1:1234" in lowered


def _extract_message_content(response: Any) -> str:
    choices = response.get("choices") if isinstance(response, dict) else getattr(response, "choices", None)
    if not choices:
        raise LLMUnavailableError("LLM returned an empty response.")
    message = choices[0].get("message") if isinstance(choices[0], dict) else getattr(choices[0], "message", None)
    content = message.get("content") if isinstance(message, dict) else getattr(message, "content", "")
    return (content or "").strip()


class LiteLLMTransport(LLMTransport):
    def generate(self, request: LLMRequest) -> str:
        if litellm is None:
            message = "LLM support is unavailable (litellm not installed)."
            if request.raise_on_error:
                raise LLMUnavailableError(message)
            return f"[LLM unavailable: {message}]"

        provider = (settings.llm_provider or "openai").strip().lower()
        api_base = settings.llm_api_base
        params: dict[str, Any] = {
            "model": request.model or settings.llm_model or "gpt-4o-mini",
            "messages": list(request.messages),
            "temperature": request.temperature if request.temperature is not None else settings.llm_temperature,
        }
        effective_max_tokens = (
            request.max_tokens if request.max_tokens is not None else settings.llm_max_tokens_explanation
        )
        if effective_max_tokens is not None:
            params["max_tokens"] = effective_max_tokens
        if request.stop is not None:
            params["stop"] = request.stop
        if request.response_format is not None:
            params["response_format"] = request.response_format
        if settings.llm_api_key:
            params["api_key"] = settings.llm_api_key
        if api_base:
            params["api_base"] = api_base
        if provider:
            params["custom_llm_provider"] = provider

        extra_body: dict[str, Any] = {}
        if not settings.llm_enable_thinking:
            extra_body["enable_thinking"] = False
            extra_body["chat_template_kwargs"] = {"enable_thinking": False}

        effective_ttl = request.ttl_seconds if request.ttl_seconds is not None else settings.llm_model_ttl_seconds
        if effective_ttl is not None and _is_lm_studio_api_base(api_base):
            extra_body["ttl"] = int(effective_ttl)

        if extra_body:
            params["extra_body"] = extra_body

        try:
            response = litellm.completion(**params)  # type: ignore[arg-type]
            return _extract_message_content(response)
        except LLMUnavailableError:
            message = "LLM returned an empty response."
            if request.raise_on_error:
                raise
            return f"[LLM unavailable: {message}]"
        except Exception as exc:  # pragma: no cover - runtime guard
            logger.exception(
                "LLM completion failed (provider=%s model=%s api_base=%s)",
                provider,
                params.get("model"),
                api_base,
            )
            message = _humanize_llm_failure(exc, api_base=api_base)
            if request.raise_on_error:
                raise LLMUnavailableError(message) from exc
            return f"[LLM unavailable: {message}]"
