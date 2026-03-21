from __future__ import annotations

import logging
from typing import Any

from openai import OpenAI

from codegraph.config import settings
from codegraph.llm.transport.base import LLMRequest, LLMTransport, LLMUnavailableError


logger = logging.getLogger("codegraph.llm.transport.openai_compatible")


def _summarize_exception(exc: Exception) -> str:
    msg = str(exc).strip() or exc.__class__.__name__
    if "Traceback" in msg:
        msg = msg.split("Traceback", 1)[0].strip(" :-\n\t")
    if len(msg) > 300:
        msg = msg[:300].rstrip() + "..."
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


def _build_client(*, api_base: str | None, api_key: str | None) -> OpenAI:
    # LM Studio accepts any api_key token for OpenAI-compatible mode.
    effective_api_key = api_key or ("lm-studio" if _is_lm_studio_api_base(api_base) else None)
    kwargs: dict[str, Any] = {}
    if api_base:
        kwargs["base_url"] = api_base
    if effective_api_key is not None:
        kwargs["api_key"] = effective_api_key
    return OpenAI(**kwargs)


def _extract_message_content(response: Any) -> str:
    choices = getattr(response, "choices", None)
    if not choices:
        raise LLMUnavailableError("LLM returned an empty response.")
    message = getattr(choices[0], "message", None)
    content = getattr(message, "content", "") if message is not None else ""
    if isinstance(content, list):
        parts: list[str] = []
        for part in content:
            text = getattr(part, "text", None)
            if isinstance(text, str):
                parts.append(text)
        content = "".join(parts)
    return (content or "").strip()


def _extract_responses_output_text(response: Any) -> str:
    output_text = getattr(response, "output_text", None)
    if isinstance(output_text, str) and output_text.strip():
        return output_text.strip()

    output_items = getattr(response, "output", None) or []
    text_parts: list[str] = []
    for item in output_items:
        content = getattr(item, "content", None) or []
        for part in content:
            if getattr(part, "type", None) == "output_text":
                text = getattr(part, "text", None)
                if isinstance(text, str):
                    text_parts.append(text)
            if getattr(part, "type", None) == "text":
                text = getattr(part, "text", None)
                if isinstance(text, str):
                    text_parts.append(text)
    text = "".join(text_parts).strip()
    if text:
        return text
    raise LLMUnavailableError("LLM returned an empty response.")


def _to_responses_format(response_format: dict[str, Any]) -> dict[str, Any] | None:
    if response_format.get("type") != "json_schema":
        return None
    schema_cfg = response_format.get("json_schema")
    if not isinstance(schema_cfg, dict):
        return None
    name = schema_cfg.get("name")
    schema = schema_cfg.get("schema")
    strict = schema_cfg.get("strict")
    if not isinstance(name, str) or not isinstance(schema, dict):
        return None
    payload: dict[str, Any] = {
        "type": "json_schema",
        "name": name,
        "schema": schema,
    }
    if isinstance(strict, bool):
        payload["strict"] = strict
    return payload


class OpenAICompatibleTransport(LLMTransport):
    def generate(self, request: LLMRequest) -> str:
        api_base = settings.llm_api_base
        client = _build_client(api_base=api_base, api_key=settings.llm_api_key)
        model = request.model or settings.llm_model or "gpt-4o-mini"

        effective_max_tokens = (
            request.max_tokens if request.max_tokens is not None else settings.llm_max_tokens_explanation
        )

        is_lm_studio = _is_lm_studio_api_base(api_base)

        # LM Studio documents schema-constrained output on chat/completions.
        use_chat_completions = bool(request.response_format) and is_lm_studio

        extra_body: dict[str, Any] = {}
        if is_lm_studio and not settings.llm_enable_thinking:
            extra_body["enable_thinking"] = False
            extra_body["chat_template_kwargs"] = {"enable_thinking": False}

        effective_ttl = request.ttl_seconds if request.ttl_seconds is not None else settings.llm_model_ttl_seconds
        if is_lm_studio and effective_ttl is not None:
            extra_body["ttl"] = int(effective_ttl)

        try:
            if use_chat_completions:
                params: dict[str, Any] = {
                    "model": model,
                    "messages": list(request.messages),
                    "temperature": request.temperature if request.temperature is not None else settings.llm_temperature,
                }
                if effective_max_tokens is not None:
                    params["max_tokens"] = effective_max_tokens
                if request.stop is not None:
                    params["stop"] = request.stop
                if request.response_format is not None:
                    params["response_format"] = request.response_format
                if extra_body:
                    params["extra_body"] = extra_body

                response = client.chat.completions.create(**params)
                return _extract_message_content(response)

            params = {
                "model": model,
                "input": list(request.messages),
                "temperature": request.temperature if request.temperature is not None else settings.llm_temperature,
            }
            if effective_max_tokens is not None:
                params["max_output_tokens"] = effective_max_tokens

            if request.response_format is not None:
                mapped_format = _to_responses_format(request.response_format)
                if mapped_format is None:
                    raise LLMUnavailableError("Unsupported response_format for responses endpoint.")
                params["text"] = {"format": mapped_format}
            if extra_body:
                params["extra_body"] = extra_body

            response = client.responses.create(**params)
            return _extract_responses_output_text(response)
        except LLMUnavailableError:
            message = "LLM returned an empty response."
            if request.raise_on_error:
                raise
            return f"[LLM unavailable: {message}]"
        except Exception as exc:  # pragma: no cover - runtime guard
            logger.exception(
                "LLM completion failed (model=%s api_base=%s endpoint=%s)",
                model,
                api_base,
                "chat.completions" if use_chat_completions else "responses",
            )
            message = _humanize_llm_failure(exc, api_base=api_base)
            if request.raise_on_error:
                raise LLMUnavailableError(message) from exc
            return f"[LLM unavailable: {message}]"
