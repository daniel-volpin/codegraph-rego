from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from codegraph.config import settings
from codegraph.llm.transport.base import LLMRequest, LLMUnavailableError


def summarize_exception(exc: Exception) -> str:
    msg = str(exc).strip() or exc.__class__.__name__
    if "Traceback" in msg:
        msg = msg.split("Traceback", 1)[0].strip(" :-\n\t")
    if len(msg) > 300:
        msg = msg[:300].rstrip() + "..."
    return msg


def humanize_llm_failure(exc: Exception, *, api_base: str | None) -> str:
    summary = summarize_exception(exc)
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


def is_lm_studio_api_base(api_base: str | None) -> bool:
    if not api_base:
        return False
    lowered = api_base.lower()
    return "localhost:1234" in lowered or "127.0.0.1:1234" in lowered


def is_local_model_name(model_name: str) -> bool:
    lowered = model_name.lower()
    return any(
        kw in lowered
        for kw in ("qwen", "gemma", "llama", "mistral", "mlx", "deepseek", "phi", "starcoder", "codellama")
    )


def is_reasoning_model(model_name: str) -> bool:
    lowered = model_name.lower()
    return lowered.startswith(("o1", "o3", "o4", "gpt-5"))


def resolve_effective_api_base(configured_base: str | None, model: str) -> str | None:
    if configured_base and not ("api.openai.com" in configured_base and is_local_model_name(model)):
        return configured_base
    if is_local_model_name(model):
        return "http://127.0.0.1:1234/v1"
    return configured_base


def infer_provider(api_base: str | None) -> str:
    if not api_base:
        return "openai"
    lowered = api_base.lower()
    if "localhost" in lowered or "127.0.0.1" in lowered:
        return "lmstudio"
    if "anthropic" in lowered:
        return "anthropic"
    return "openai"


def to_responses_format(response_format: dict[str, Any]) -> dict[str, Any] | None:
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
class GenerationConfig:
    api_base: str | None
    model: str
    max_tokens: int | None
    temperature: float | None
    use_chat_completions: bool
    extra_body: dict[str, Any]


def generation_config(request: LLMRequest, settings_obj=None) -> GenerationConfig:
    cfg = settings_obj if settings_obj is not None else settings
    model_name = request.model or cfg.llm_model or "gpt-4o-mini"
    api_base = resolve_effective_api_base(cfg.llm_api_base, model_name)
    is_lm_studio = is_lm_studio_api_base(api_base)
    extra_body: dict[str, Any] = {}
    if is_lm_studio and not cfg.llm_enable_thinking:
        extra_body["enable_thinking"] = False
        extra_body["chat_template_kwargs"] = {"enable_thinking": False}

    effective_ttl = request.ttl_seconds if request.ttl_seconds is not None else cfg.llm_model_ttl_seconds
    if is_lm_studio and effective_ttl is not None:
        extra_body["ttl"] = int(effective_ttl)

    return GenerationConfig(
        api_base=api_base,
        model=model_name,
        max_tokens=request.max_tokens if request.max_tokens is not None else cfg.llm_max_tokens_explanation,
        temperature=(
            (request.temperature if request.temperature is not None else cfg.llm_temperature)
            if cfg.llm_send_temperature else None
        ),
        use_chat_completions=(
            request.tools is not None
            or cfg.llm_api_mode == "chat_completions"
            or (cfg.llm_api_mode == "auto" and is_lm_studio)
        ),
        extra_body=extra_body,
    )


def set_common_span_attributes(
    span: Any,
    request: LLMRequest,
    config: GenerationConfig,
    *,
    task_type: str,
    retry_index: int,
) -> None:
    provider = infer_provider(config.api_base)
    span.set_attribute("openinference.span.kind", "LLM")
    span.set_attribute("llm.model", config.model)
    span.set_attribute("llm.model_name", config.model)
    span.set_attribute("llm.provider", provider)
    span.set_attribute("gen_ai.system", provider)
    span.set_attribute("gen_ai.request.model", config.model)
    span.set_attribute("llm.base_url", config.api_base or "")
    if config.temperature is not None:
        span.set_attribute("llm.temperature", config.temperature)
        span.set_attribute("gen_ai.request.temperature", config.temperature)
    span.set_attribute("llm.max_tokens", config.max_tokens if config.max_tokens is not None else -1)
    span.set_attribute("gen_ai.request.max_tokens", config.max_tokens if config.max_tokens is not None else -1)
    span.set_attribute("llm.task_type", task_type)
    span.set_attribute("llm.response_format", str(request.response_format is not None))
    span.set_attribute("llm.retry_index", retry_index)


def chat_completion_params(request: LLMRequest, config: GenerationConfig) -> dict[str, Any]:
    params: dict[str, Any] = {
        "model": config.model,
        "messages": list(request.messages),
    }
    if config.temperature is not None:
        params["temperature"] = config.temperature
    if config.max_tokens is not None:
        key = "max_completion_tokens" if is_reasoning_model(config.model) else "max_tokens"
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


def responses_params(request: LLMRequest, config: GenerationConfig) -> dict[str, Any]:
    params: dict[str, Any] = {
        "model": config.model,
        "input": list(request.messages),
    }
    if config.temperature is not None:
        params["temperature"] = config.temperature
    if config.max_tokens is not None:
        params["max_output_tokens"] = config.max_tokens
    if request.response_format is not None:
        mapped_format = to_responses_format(request.response_format)
        if mapped_format is None:
            raise LLMUnavailableError("Unsupported response_format for responses endpoint.")
        params["text"] = {"format": mapped_format}
    if config.extra_body:
        params["extra_body"] = config.extra_body
    return params
