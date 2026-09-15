from __future__ import annotations

import logging
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import httpx2
from openai import OpenAI

from codegraph.config import settings
from codegraph.llm.schema.explanation import strip_structured_stop_tokens
from codegraph.llm.transport.base import LLMRequest, LLMTransport, LLMUnavailableError
from codegraph.llm.transport.provider_admission import provider_admission_gate
from codegraph.llm.usage import record_llm_usage
from codegraph.telemetry import get_tracer

logger = logging.getLogger("codegraph.llm.transport.openai_compatible")
_tracer = get_tracer("codegraph.llm.transport")
_CLIENT_CLOSE_EXCEPTIONS = (RuntimeError, OSError, httpx2.HTTPError)


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


def _is_local_model_name(model_name: str) -> bool:
    lowered = model_name.lower()
    return any(
        kw in lowered
        for kw in ("qwen", "gemma", "llama", "mistral", "mlx", "deepseek", "phi", "starcoder", "codellama")
    )


def _is_reasoning_model(model_name: str) -> bool:
    """OpenAI's o1/o3/o4/gpt-5 family rejects `max_tokens` on chat.completions,
    requiring `max_completion_tokens` instead."""
    lowered = model_name.lower()
    return lowered.startswith(("o1", "o3", "o4", "gpt-5"))


def _resolve_effective_api_base(configured_base: str | None, model: str) -> str | None:
    if configured_base and not ("api.openai.com" in configured_base and _is_local_model_name(model)):
        return configured_base
    if _is_local_model_name(model):
        return "http://127.0.0.1:1234/v1"
    return configured_base


def _infer_provider(api_base: str | None) -> str:
    if not api_base:
        return "openai"
    lowered = api_base.lower()
    if "localhost" in lowered or "127.0.0.1" in lowered:
        return "lmstudio"
    if "anthropic" in lowered:
        return "anthropic"
    return "openai"


def _build_client(*, api_base: str | None, api_key: str | None) -> OpenAI:
    # LM Studio accepts any api_key token for OpenAI-compatible mode.
    effective_api_key = api_key or ("lm-studio" if _is_lm_studio_api_base(api_base) else None)
    kwargs: dict[str, Any] = {
        "timeout": settings.llm_timeout_seconds,
        "max_retries": settings.llm_max_retries,
    }
    if api_base:
        kwargs["base_url"] = api_base
    if effective_api_key is not None:
        kwargs["api_key"] = effective_api_key
    return OpenAI(**kwargs)


def _extract_message_content(response: Any, *, allow_reasoning_content: bool = False) -> str:
    choices = getattr(response, "choices", None)
    if not choices:
        raise LLMUnavailableError("LLM returned an empty response.")
    finish_reason = getattr(choices[0], "finish_reason", None)
    if isinstance(finish_reason, str):
        normalized_finish_reason = finish_reason.strip().lower()
        if normalized_finish_reason == "length":
            raise LLMUnavailableError("LLM response is incomplete (finish_reason=length).")
        if normalized_finish_reason == "content_filter":
            raise LLMUnavailableError("LLM response was blocked by content filtering.")
    message = getattr(choices[0], "message", None)
    refusal = getattr(message, "refusal", None)
    if isinstance(refusal, str) and refusal:
        raise LLMUnavailableError("LLM refused the request.")
    content = getattr(message, "content", "") if message is not None else ""
    if isinstance(content, list):
        parts: list[str] = []
        for part in content:
            text = getattr(part, "text", None)
            if isinstance(text, str):
                parts.append(text)
        content = "".join(parts)
    text = (content or "").strip()
    if text:
        return text
    if allow_reasoning_content and message is not None:
        reasoning_content = getattr(message, "reasoning_content", None)
        if isinstance(reasoning_content, str):
            salvaged = strip_structured_stop_tokens(reasoning_content)
            if salvaged:
                return salvaged
    raise LLMUnavailableError("LLM returned an empty response.")


def _extract_responses_output_text(response: Any) -> str:
    status = getattr(response, "status", None)
    if isinstance(status, str) and status != "completed":
        raise LLMUnavailableError(f"LLM response is {status}.")

    output_items = getattr(response, "output", None) or []
    for item in output_items:
        content = getattr(item, "content", None) or []
        for part in content:
            if getattr(part, "type", None) == "refusal":
                raise LLMUnavailableError("LLM refused the request.")

    output_text = getattr(response, "output_text", None)
    if isinstance(output_text, str) and output_text.strip():
        return output_text.strip()

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


@dataclass(frozen=True)
class _GenerationConfig:
    api_base: str | None
    model: str
    max_tokens: int | None
    temperature: float | None
    use_chat_completions: bool
    extra_body: dict[str, Any]


def _generation_config(request: LLMRequest) -> _GenerationConfig:
    model_name = request.model or settings.llm_model or "gpt-4o-mini"
    api_base = _resolve_effective_api_base(settings.llm_api_base, model_name)
    is_lm_studio = _is_lm_studio_api_base(api_base)
    extra_body: dict[str, Any] = {}
    if is_lm_studio and not settings.llm_enable_thinking:
        extra_body["enable_thinking"] = False
        extra_body["chat_template_kwargs"] = {"enable_thinking": False}

    effective_ttl = request.ttl_seconds if request.ttl_seconds is not None else settings.llm_model_ttl_seconds
    if is_lm_studio and effective_ttl is not None:
        extra_body["ttl"] = int(effective_ttl)

    return _GenerationConfig(
        api_base=api_base,
        model=model_name,
        max_tokens=request.max_tokens if request.max_tokens is not None else settings.llm_max_tokens_explanation,
        temperature=(
            (request.temperature if request.temperature is not None else settings.llm_temperature)
            if settings.llm_send_temperature else None
        ),
        use_chat_completions=(
            request.tools is not None
            or settings.llm_api_mode == "chat_completions"
            or (settings.llm_api_mode == "auto" and is_lm_studio)
        ),
        extra_body=extra_body,
    )


def _set_common_span_attributes(
    span: Any,
    request: LLMRequest,
    config: _GenerationConfig,
    *,
    task_type: str,
    retry_index: int,
) -> None:
    span.set_attribute("llm.model", config.model)
    span.set_attribute("llm.provider", _infer_provider(config.api_base))
    span.set_attribute("llm.base_url", config.api_base or "")
    if config.temperature is not None:
        span.set_attribute("llm.temperature", config.temperature)
    span.set_attribute("llm.max_tokens", config.max_tokens if config.max_tokens is not None else -1)
    span.set_attribute("llm.task_type", task_type)
    span.set_attribute("llm.response_format", str(request.response_format is not None))
    span.set_attribute("llm.retry_index", retry_index)


def _token_count(usage: Any, name: str) -> int:
    value = getattr(usage, name, -1)
    return value if isinstance(value, int) and value >= 0 else -1


def _nested_count(parent: Any, container_name: str, field_name: str) -> int:
    container = getattr(parent, container_name, None)
    if container is None:
        return 0
    value = getattr(container, field_name, None)
    return value if isinstance(value, int) and value > 0 else 0


def _usage_detail_counts(usage: Any, token_names: Mapping[str, str]) -> tuple[int, int]:
    """Cached input and reasoning output counts, when the provider reports them.

    Cached input is billed at a discount, so ignoring it overstates cost.
    Reasoning output is already inside the output count and is carried only for
    visibility. The two response shapes name these containers differently, so
    the detail field names are derived from the same mapping that selects the
    top-level counts. Locally served models report neither; zero is correct.
    """
    if usage is None:
        return 0, 0
    input_container = f"{token_names['prompt']}_details"
    output_container = f"{token_names['completion']}_details"
    cached = _nested_count(usage, input_container, "cached_tokens")
    reasoning = _nested_count(usage, output_container, "reasoning_tokens")
    return cached, reasoning


def _set_usage_attributes(
    span: Any,
    usage: Any,
    token_names: Mapping[str, str],
    *,
    config: _GenerationConfig | None = None,
    task_type: str = "",
    duration_seconds: float | None = None,
) -> None:
    """Annotate the span and record the call in the usage ledger.

    Every provider reaches this one function, so OpenAI-hosted and locally
    served models are accounted for identically.
    """
    prompt_units = -1
    completion_units = -1
    total_units = -1
    if usage is not None:
        prompt_units = _token_count(usage, token_names["prompt"])
        completion_units = _token_count(usage, token_names["completion"])
        if token_names["total"]:
            total_units = _token_count(usage, token_names["total"])
        else:
            total_units = max(0, prompt_units) + max(0, completion_units)

    span.set_attribute("llm.prompt_tokens", prompt_units)
    span.set_attribute("llm.completion_tokens", completion_units)
    span.set_attribute("llm.total_tokens", total_units or -1)
    # Also under the GenAI semantic conventions, so a collector that already
    # knows them need not learn this codebase's own attribute names.
    span.set_attribute("gen_ai.usage.input_tokens", prompt_units)
    span.set_attribute("gen_ai.usage.output_tokens", completion_units)

    if config is not None:
        cached, reasoning = _usage_detail_counts(usage, token_names)
        record_llm_usage(
            provider=_infer_provider(config.api_base),
            model=config.model or "unknown",
            task_type=task_type or "unknown",
            input_units=prompt_units,
            output_units=completion_units,
            cached_input_units=cached,
            reasoning_output_units=reasoning,
            duration_seconds=duration_seconds,
        )


def _chat_completion_params(request: LLMRequest, config: _GenerationConfig) -> dict[str, Any]:
    params: dict[str, Any] = {
        "model": config.model,
        "messages": list(request.messages),
    }
    if config.temperature is not None:
        params["temperature"] = config.temperature
    if config.max_tokens is not None:
        key = "max_completion_tokens" if _is_reasoning_model(config.model) else "max_tokens"
        params[key] = config.max_tokens
    if request.stop is not None:
        params["stop"] = request.stop
    if request.response_format is not None:
        params["response_format"] = request.response_format
    if request.tools is not None:
        params["tools"] = list(request.tools)
        params["tool_choice"] = "auto"
    if config.extra_body:
        params["extra_body"] = config.extra_body
    return params


def _responses_params(request: LLMRequest, config: _GenerationConfig) -> dict[str, Any]:
    params: dict[str, Any] = {
        "model": config.model,
        "input": list(request.messages),
    }
    if config.temperature is not None:
        params["temperature"] = config.temperature
    if config.max_tokens is not None:
        params["max_output_tokens"] = config.max_tokens
    if request.response_format is not None:
        mapped_format = _to_responses_format(request.response_format)
        if mapped_format is None:
            raise LLMUnavailableError("Unsupported response_format for responses endpoint.")
        params["text"] = {"format": mapped_format}
    if config.extra_body:
        params["extra_body"] = config.extra_body
    return params


def _generate_with_chat_completions(
    client: OpenAI, request: LLMRequest, config: _GenerationConfig, span: Any, task_type: str = ""
) -> Any:
    started = time.perf_counter()
    response = client.chat.completions.create(**_chat_completion_params(request, config))
    _set_usage_attributes(
        span,
        getattr(response, "usage", None),
        {"prompt": "prompt_tokens", "completion": "completion_tokens", "total": "total_tokens"},
        config=config,
        task_type=task_type,
        duration_seconds=time.perf_counter() - started,
    )
    if request.tools:
        choices = getattr(response, "choices", None) or []
        msg = choices[0].message if choices else None
        if choices and not getattr(msg, "tool_calls", None) and not getattr(msg, "content", None):
            logger.info(
                "empty_response finish_reason=%s message=%s",
                getattr(choices[0], "finish_reason", None),
                msg,
            )
        tool_calls = []
        for tc in getattr(msg, "tool_calls", None) or []:
            tool_calls.append(
                {
                    "id": getattr(tc, "id", None),
                    "type": getattr(tc, "type", "function"),
                    "function": {
                        "name": getattr(tc.function, "name", ""),
                        "arguments": getattr(tc.function, "arguments", "{}"),
                    },
                }
            )
        return {
            "choices": [
                {
                    "message": {
                        "content": getattr(msg, "content", ""),
                        "tool_calls": tool_calls,
                    }
                }
            ]
        }
    return _extract_message_content(response, allow_reasoning_content=request.response_format is not None)


def _generate_with_responses(
    client: OpenAI, request: LLMRequest, config: _GenerationConfig, span: Any, task_type: str = ""
) -> str:
    started = time.perf_counter()
    response = client.responses.create(**_responses_params(request, config))
    _set_usage_attributes(
        span,
        getattr(response, "usage", None),
        {"prompt": "input_tokens", "completion": "output_tokens", "total": ""},
        config=config,
        task_type=task_type,
        duration_seconds=time.perf_counter() - started,
    )
    return _extract_responses_output_text(response)


class OpenAICompatibleTransport(LLMTransport):
    def generate(self, request: LLMRequest, *, task_type: str = "", retry_index: int = 0) -> str:
        config = _generation_config(request)

        with _tracer.start_as_current_span("llm.generate") as span:
            _set_common_span_attributes(span, request, config, task_type=task_type, retry_index=retry_index)

            t0 = time.monotonic()
            client = None
            close_error: RuntimeError | OSError | httpx2.HTTPError | None = None
            output_text: str | None = None
            generation_error_message: str | None = None
            generation_exception: LLMUnavailableError | None = None
            generation_cause: Exception | None = None
            try:
                with provider_admission_gate.acquire(
                    max_active=settings.llm_max_concurrent_requests,
                    max_waiting=settings.llm_max_pending_requests,
                    queue_timeout_seconds=settings.llm_queue_timeout_seconds,
                ):
                    try:
                        client = _build_client(api_base=config.api_base, api_key=settings.llm_api_key)
                        if config.use_chat_completions:
                            output_text = _generate_with_chat_completions(client, request, config, span, task_type)
                        else:
                            output_text = _generate_with_responses(client, request, config, span, task_type)
                    finally:
                        if client is not None:
                            try:
                                client.close()
                            except _CLIENT_CLOSE_EXCEPTIONS as exc:
                                close_error = exc
                                span.set_attribute("llm.close_error", _summarize_exception(exc))
                                logger.warning("Failed to close LLM client cleanly: %s", _summarize_exception(exc))
            except LLMUnavailableError as exc:
                error_msg = str(exc) or "LLM returned an empty response."
                generation_exception = exc
                generation_error_message = error_msg
                span.set_attribute("llm.error", error_msg)
            except Exception as exc:  # pragma: no cover - runtime guard
                logger.exception(
                    "LLM completion failed (model=%s api_base=%s endpoint=%s)",
                    config.model,
                    config.api_base,
                    "chat.completions" if config.use_chat_completions else "responses",
                )
                error_msg = _humanize_llm_failure(exc, api_base=config.api_base)
                generation_exception = LLMUnavailableError(error_msg)
                generation_error_message = error_msg
                generation_cause = exc
                span.set_attribute("llm.error", error_msg)
            finally:
                span.set_attribute("llm.latency_ms", round((time.monotonic() - t0) * 1000))

            if generation_error_message is not None:
                if request.raise_on_error and generation_exception is not None:
                    if generation_cause is not None:
                        raise generation_exception from generation_cause
                    raise generation_exception
                return f"[LLM unavailable: {generation_error_message}]"

            if close_error is not None:
                close_error_message = f"LLM client cleanup failed: {_summarize_exception(close_error)}"
                span.set_attribute("llm.error", close_error_message)
                if request.raise_on_error:
                    raise LLMUnavailableError(close_error_message) from close_error
                return f"[LLM unavailable: {close_error_message}]"

            if output_text is not None:
                return output_text
            raise LLMUnavailableError("LLM returned an empty response.")
