from __future__ import annotations

import logging
import time
from typing import Any

import httpx2
from openai import OpenAI

from codegraph.config import settings
from codegraph.llm.transport.base import LLMRequest, LLMTransport, LLMUnavailableError
from codegraph.llm.transport.openai_compatible_config import (
    generation_config as _generation_config,
)
from codegraph.llm.transport.openai_compatible_config import (
    humanize_llm_failure as _humanize_llm_failure,
)
from codegraph.llm.transport.openai_compatible_config import (
    infer_provider as _infer_provider,
)
from codegraph.llm.transport.openai_compatible_config import (
    is_lm_studio_api_base as _is_lm_studio_api_base,
)
from codegraph.llm.transport.openai_compatible_config import (
    is_local_model_name as _is_local_model_name,
)
from codegraph.llm.transport.openai_compatible_config import (
    is_reasoning_model as _is_reasoning_model,
)
from codegraph.llm.transport.openai_compatible_config import (
    resolve_effective_api_base as _resolve_effective_api_base,
)
from codegraph.llm.transport.openai_compatible_config import (
    set_common_span_attributes as _set_common_span_attributes,
)
from codegraph.llm.transport.openai_compatible_config import (
    summarize_exception as _summarize_exception,
)
from codegraph.llm.transport.openai_compatible_config import (
    to_responses_format as _to_responses_format,
)
from codegraph.llm.transport.openai_compatible_invoker import (
    extract_message_content as _extract_message_content,
)
from codegraph.llm.transport.openai_compatible_invoker import (
    extract_responses_output_text as _extract_responses_output_text,
)
from codegraph.llm.transport.openai_compatible_invoker import (
    generate_with_chat_completions as _generate_with_chat_completions,
)
from codegraph.llm.transport.openai_compatible_invoker import (
    generate_with_responses as _generate_with_responses,
)
from codegraph.llm.transport.openai_compatible_invoker import (
    nested_count as _nested_count,
)
from codegraph.llm.transport.openai_compatible_invoker import (
    set_usage_attributes as _set_usage_attributes,
)
from codegraph.llm.transport.openai_compatible_invoker import (
    token_count as _token_count,
)
from codegraph.llm.transport.openai_compatible_invoker import (
    usage_detail_counts as _usage_detail_counts,
)
from codegraph.llm.transport.provider_admission import provider_admission_gate
from codegraph.telemetry import get_tracer

__all__ = [
    "OpenAI",
    "OpenAICompatibleTransport",
    "_extract_message_content",
    "_extract_responses_output_text",
    "_generation_config",
    "_humanize_llm_failure",
    "_infer_provider",
    "_is_lm_studio_api_base",
    "_is_local_model_name",
    "_is_reasoning_model",
    "_nested_count",
    "_resolve_effective_api_base",
    "_set_common_span_attributes",
    "_set_usage_attributes",
    "_summarize_exception",
    "_to_responses_format",
    "_token_count",
    "_usage_detail_counts",
    "provider_admission_gate",
    "settings",
]

logger = logging.getLogger("codegraph.llm.transport.openai_compatible")
_tracer = get_tracer("codegraph.llm.transport")
_CLIENT_CLOSE_EXCEPTIONS = (RuntimeError, OSError, httpx2.HTTPError)


def _build_client(*, api_base: str | None, api_key: str | None) -> OpenAI:
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


class OpenAICompatibleTransport(LLMTransport):
    def generate(self, request: LLMRequest, *, task_type: str = "", retry_index: int = 0) -> str:
        config = _generation_config(request, settings)

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
