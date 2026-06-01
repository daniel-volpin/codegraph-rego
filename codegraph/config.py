import ipaddress
import os
from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[1]
LOCAL_ENV_FILE = PROJECT_ROOT / ".env"
ENV_FILE_OVERRIDE_VAR = "CODEGRAPH_ENV_FILE"


class Settings(BaseSettings):
    backend_host: str = Field(
        "127.0.0.1",
        validation_alias=AliasChoices("CODEGRAPH_HOST", "backend_host"),
        description="Bind host for the local backend service. Defaults to loopback for safe local-only operation.",
    )
    cors_allowed_origins: list[str] = Field(
        default_factory=lambda: [
            "http://127.0.0.1:5173",
            "http://localhost:5173",
            "http://127.0.0.1:4173",
            "http://localhost:4173",
            "http://127.0.0.1:8000",
            "http://localhost:8000",
        ],
        description="Allowed browser origins for the local frontend and backend tools.",
    )
    index_dir: str = Field("index", description="Index directory")
    faiss_index_path: str = Field("index/code_embeddings.index", description="FAISS index path")
    signature_map_path: str = Field("index/embedding_signature_map.json", description="Signature map path")
    signature_map_path_full: str = Field(
        "index/embedding_full_signature_map.json", description="Full signature map path"
    )
    embedding_metadata_path: str = Field("index/embedding_metadata.json", description="Embedding metadata path")
    embedding_cache_path: str = Field("index/embedding_cache.json", description="Embedding cache path")
    embedding_model_name: str = Field("all-MiniLM-L6-v2", description="Embedding model name")
    upload_dir: str = Field("uploaded_code", description="Upload directory")
    java_root_dir: str = Field("uploaded_code", description="Java root directory")
    upload_max_archive_size_bytes: int = Field(
        100 * 1024 * 1024,
        gt=0,
        description="Maximum uploaded ZIP size",
    )
    upload_max_member_size_bytes: int = Field(
        50 * 1024 * 1024,
        gt=0,
        description="Maximum uncompressed ZIP member size",
    )
    upload_max_extracted_size_bytes: int = Field(
        500 * 1024 * 1024,
        gt=0,
        description="Maximum total uncompressed bytes extracted from a ZIP",
    )
    upload_max_archive_entries: int = Field(10_000, gt=0, description="Maximum number of entries allowed in a ZIP")
    upload_max_compression_ratio: float = Field(
        100.0,
        ge=1.0,
        description="Maximum allowed ZIP compression ratio per member",
    )
    neo4j_uri: str = Field(
        "bolt://localhost:7687",
        validation_alias=AliasChoices("NEO4J_URI", "neo4j_uri"),
        description="Neo4j URI",
    )
    neo4j_user: str = Field(
        "neo4j",
        validation_alias=AliasChoices("NEO4J_USER", "neo4j_user"),
        description="Neo4j user",
    )
    neo4j_pass: str | None = Field(
        None,
        validation_alias=AliasChoices("NEO4J_PASS", "neo4j_pass"),
        description="Neo4j password",
    )
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
        1024,
        gt=0,
        validation_alias=AliasChoices("LLM_MAX_TOKENS_REMEDIATION", "llm_max_tokens_remediation"),
        description="Maximum tokens to generate for remediation calls.",
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
        2,
        ge=1,
        validation_alias=AliasChoices("LLM_CONCURRENCY", "llm_concurrency"),
        description=(
            "Maximum number of concurrent LLM HTTP requests. Keep at 2 for local models "
            "(LM Studio handles limited parallelism). Increase for hosted APIs."
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
    ui_review_store_path: str = Field(
        "outputs/policy_ui_reviews/reviews.jsonl",
        description="Append-only JSONL store for UI triage/review records.",
    )

    model_config = SettingsConfigDict(extra="ignore")

    @field_validator("backend_host")
    @classmethod
    def _validate_backend_host(cls, value: str) -> str:
        if value == "localhost":
            return value
        ipaddress.ip_address(value)
        return value


def resolve_explicit_env_file() -> str | None:
    configured = os.environ.get(ENV_FILE_OVERRIDE_VAR)
    if not configured:
        return None
    return configured


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    env_file = resolve_explicit_env_file()
    if env_file:
        return Settings(_env_file=env_file)
    return Settings()


def clear_settings_cache() -> None:
    get_settings.cache_clear()


def validate_runtime_settings(candidate: Settings | None = None) -> Settings:
    settings_obj = candidate or get_settings()
    missing: list[str] = []
    if not settings_obj.neo4j_pass:
        missing.append("NEO4J_PASS")
    if missing:
        raise ValueError(f"Missing required runtime setting(s): {', '.join(missing)}")
    return settings_obj


class _SettingsProxy:
    def __getattr__(self, name: str) -> Any:
        return getattr(get_settings(), name)


settings = _SettingsProxy()
