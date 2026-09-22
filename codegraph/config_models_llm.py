from __future__ import annotations

from typing import Literal

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings


class BaseLLMSettings(BaseSettings):
    llm_model: str = Field(
        "gpt-4o-mini",
        validation_alias=AliasChoices("LLM_MODEL", "llm_model"),
        description="LLM model",
    )
    llm_api_base: str | None = Field(
        None,
        validation_alias=AliasChoices("LLM_API_BASE", "llm_api_base"),
        description="LLM API base",
    )
    llm_api_key: str | None = Field(
        None,
        validation_alias=AliasChoices("LLM_API_KEY", "llm_api_key"),
        description="LLM API key",
    )
    llm_api_mode: Literal["auto", "responses", "chat_completions"] = Field(
        "auto",
        description="Explicit provider endpoint; auto preserves hosted Responses and local LM Studio Chat behavior.",
    )
    llm_timeout_seconds: float = Field(
        360.0, gt=0, le=600, description="HTTP request timeout for model calls, not a total agent-run deadline.",
    )
    llm_max_concurrent_requests: int = Field(
        1,
        ge=1,
        le=32,
        validation_alias=AliasChoices("LLM_MAX_CONCURRENT_REQUESTS", "llm_max_concurrent_requests"),
        description="Process-local cap on active provider SDK/client generation calls.",
    )
    llm_price_per_million: dict[str, dict[str, float]] = Field(
        default_factory=dict,
        validation_alias=AliasChoices("LLM_PRICE_PER_MILLION", "llm_price_per_million"),
        description=(
            "Per-model rates used to estimate run cost, as "
            '{"model": {"input": 1.25, "output": 10.0}} per million units. Empty by '
            "default: an unpriced model reports units without a cost rather than "
            "one guessed from a stale published rate."
        ),
    )
    llm_max_pending_requests: int = Field(
        4,
        ge=0,
        le=32,
        validation_alias=AliasChoices("LLM_MAX_PENDING_REQUESTS", "llm_max_pending_requests"),
        description="Process-local cap on generation calls waiting for provider admission.",
    )
    llm_queue_timeout_seconds: float = Field(
        60.0,
        gt=0.0,
        le=120.0,
        validation_alias=AliasChoices("LLM_QUEUE_TIMEOUT_SECONDS", "llm_queue_timeout_seconds"),
        description="Maximum queue wait for provider admission; separate from LLM HTTP request timeout.",
    )
    llm_max_retries: int = Field(
        0, ge=0, le=2, description="SDK transport retries per generation attempt; default avoids hidden retry multiplication.",
    )
    llm_send_temperature: bool = Field(
        True, description="Disable for model/provider combinations that do not accept a temperature parameter.",
    )
    llm_temperature: float = Field(
        0.2,
        ge=0.0,
        le=2.0,
        validation_alias=AliasChoices("LLM_TEMPERATURE", "llm_temperature"),
        description="LLM temperature",
    )
    llm_enable_thinking: bool = Field(
        True,
        description=(
            "Whether to allow LLM chain-of-thought <think> blocks. "
            "Set to false to suppress thinking on models that support it (Qwen3, DeepSeek)."
        ),
    )
    llm_max_tokens_explanation: int | None = Field(
        512,
        gt=0,
        validation_alias=AliasChoices("LLM_MAX_TOKENS_EXPLANATION", "llm_max_tokens_explanation"),
        description="Maximum tokens to generate for explanation calls.",
    )
    llm_max_tokens_remediation: int | None = Field(
        8192,
        gt=0,
        validation_alias=AliasChoices("LLM_MAX_TOKENS_REMEDIATION", "llm_max_tokens_remediation"),
        description="Maximum tokens to generate for remediation calls, including any reasoning content.",
    )
    llm_model_ttl_seconds: int | None = Field(
        None,
        gt=0,
        validation_alias=AliasChoices("LLM_MODEL_TTL_SECONDS", "llm_model_ttl_seconds"),
        description="Optional LM Studio model TTL (seconds) for explanation/default requests.",
    )
    remediation_llm_model: str | None = Field(
        None,
        validation_alias=AliasChoices("REMEDIATION_LLM_MODEL", "remediation_llm_model"),
        description="Optional model override for remediation generation.",
    )
    remediation_llm_max_tokens: int | None = Field(
        None,
        gt=0,
        validation_alias=AliasChoices("REMEDIATION_LLM_MAX_TOKENS", "remediation_llm_max_tokens"),
        description="Optional token cap override for remediation generation.",
    )
    remediation_llm_temperature: float | None = Field(
        None,
        ge=0.0,
        le=2.0,
        validation_alias=AliasChoices("REMEDIATION_LLM_TEMPERATURE", "remediation_llm_temperature"),
        description="Optional temperature override for remediation generation.",
    )
    remediation_llm_model_ttl_seconds: int | None = Field(
        None,
        gt=0,
        validation_alias=AliasChoices("REMEDIATION_LLM_MODEL_TTL_SECONDS", "remediation_llm_model_ttl_seconds"),
        description="Optional LM Studio model TTL (seconds) for remediation requests.",
    )
    llm_concurrency: int = Field(
        1,
        ge=1,
        validation_alias=AliasChoices("LLM_CONCURRENCY", "llm_concurrency"),
        description=(
            "Maximum number of concurrent LLM HTTP requests. Keep at 1 for local models "
            "(LM Studio handles single-stream efficiently without GPU memory thrashing)."
        ),
    )
    remediation_raw_capture_enabled: bool = Field(
        False,
        description=(
            "When true, remediation runs may write raw LLM outputs to disk for debugging on structured generation failures."
        ),
    )
    remediation_confidence_gate_enabled: bool = Field(
        True,
        description="When true, live remediation apply mode enforces a confidence gate before mutating source files.",
    )
    remediation_confidence_threshold_apply: float = Field(
        0.75,
        ge=0.0,
        le=1.0,
        validation_alias=AliasChoices(
            "REMEDIATION_CONFIDENCE_THRESHOLD_APPLY", "remediation_confidence_threshold_apply"
        ),
        description="Minimum confidence required for automatic apply in remediation apply mode.",
    )
    remediation_confidence_threshold_review: float = Field(
        0.50,
        ge=0.0,
        le=1.0,
        validation_alias=AliasChoices(
            "REMEDIATION_CONFIDENCE_THRESHOLD_REVIEW", "remediation_confidence_threshold_review"
        ),
        description="Minimum confidence for manual-review band; lower scores are abstain.",
    )
    remediation_confidence_temperature: float = Field(
        1.0,
        gt=0.0,
        validation_alias=AliasChoices("REMEDIATION_CONFIDENCE_TEMPERATURE", "remediation_confidence_temperature"),
        description="Temperature scaling for remediation confidence scoring; >1 softens confidence.",
    )
    remediation_trace_prompt_enabled: bool = Field(
        False,
        validation_alias=AliasChoices("REMEDIATION_TRACE_PROMPT_ENABLED", "remediation_trace_prompt_enabled"),
        description="When true, enriches the remediation prompt with OPA trace context when available.",
    )
