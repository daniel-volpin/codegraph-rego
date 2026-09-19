from __future__ import annotations

import logging
import time
from collections.abc import Mapping
from typing import Any

from openai import OpenAI

from codegraph.llm.schema.explanation import strip_structured_stop_tokens
from codegraph.llm.transport.base import LLMRequest, LLMUnavailableError
from codegraph.llm.transport.openai_compatible_config import (
    GenerationConfig,
    chat_completion_params,
    infer_provider,
    responses_params,
)
from codegraph.llm.usage import record_llm_usage

logger = logging.getLogger("codegraph.llm.transport.openai_compatible")


def token_count(usage: Any, name: str) -> int:
    value = getattr(usage, name, -1)
    return value if isinstance(value, int) and value >= 0 else -1


def nested_count(parent: Any, container_name: str, field_name: str) -> int:
    container = getattr(parent, container_name, None)
    if container is None:
        return 0
    value = getattr(container, field_name, None)
    return value if isinstance(value, int) and value > 0 else 0


def usage_detail_counts(usage: Any, token_names: Mapping[str, str]) -> tuple[int, int]:
    if usage is None:
        return 0, 0
    input_container = f"{token_names['prompt']}_details"
    output_container = f"{token_names['completion']}_details"
    cached = nested_count(usage, input_container, "cached_tokens")
    reasoning = nested_count(usage, output_container, "reasoning_tokens")
    return cached, reasoning


def set_usage_attributes(
    span: Any,
    usage: Any,
    token_names: Mapping[str, str],
    *,
    config: GenerationConfig | None = None,
    task_type: str = "",
    duration_seconds: float | None = None,
) -> None:
    prompt_units = -1
    completion_units = -1
    total_units = -1
    if usage is not None:
        prompt_units = token_count(usage, token_names["prompt"])
        completion_units = token_count(usage, token_names["completion"])
        if token_names["total"]:
            total_units = token_count(usage, token_names["total"])
        else:
            total_units = max(0, prompt_units) + max(0, completion_units)

    span.set_attribute("llm.prompt_tokens", prompt_units)
    span.set_attribute("llm.completion_tokens", completion_units)
    span.set_attribute("llm.total_tokens", total_units or -1)
    span.set_attribute("gen_ai.usage.input_tokens", prompt_units)
    span.set_attribute("gen_ai.usage.output_tokens", completion_units)

    if config is not None:
        cached, reasoning = usage_detail_counts(usage, token_names)
        record_llm_usage(
            provider=infer_provider(config.api_base),
            model=config.model or "unknown",
            task_type=task_type or "unknown",
            input_units=prompt_units,
            output_units=completion_units,
            cached_input_units=cached,
            reasoning_output_units=reasoning,
            duration_seconds=duration_seconds,
        )


def extract_message_content(response: Any, *, allow_reasoning_content: bool = False) -> str:
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


def extract_responses_output_text(response: Any) -> str:
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


def generate_with_chat_completions(
    client: OpenAI, request: LLMRequest, config: GenerationConfig, span: Any, task_type: str = ""
) -> Any:
    started = time.perf_counter()
    response = client.chat.completions.create(**chat_completion_params(request, config))
    set_usage_attributes(
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
    return extract_message_content(response, allow_reasoning_content=request.response_format is not None)


def generate_with_responses(
    client: OpenAI, request: LLMRequest, config: GenerationConfig, span: Any, task_type: str = ""
) -> str:
    started = time.perf_counter()
    response = client.responses.create(**responses_params(request, config))
    set_usage_attributes(
        span,
        getattr(response, "usage", None),
        {"prompt": "input_tokens", "completion": "output_tokens", "total": ""},
        config=config,
        task_type=task_type,
        duration_seconds=time.perf_counter() - started,
    )
    return extract_responses_output_text(response)
