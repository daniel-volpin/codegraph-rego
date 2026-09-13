import ipaddress
import os
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[1]
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
    llm_api_mode: Literal["auto", "responses", "chat_completions"] = Field(
        "auto",
        description="Explicit provider endpoint; auto preserves hosted Responses and local LM Studio Chat behavior.",
    )
    llm_timeout_seconds: float = Field(
        180.0, gt=0, le=600, description="HTTP request timeout for model calls, not a total agent-run deadline.",
    )
    llm_max_concurrent_requests: int = Field(
        1,
        ge=1,
        le=8,
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
    opa_timeout_seconds: float = Field(
        120.0,
        gt=0.0,
        validation_alias=AliasChoices("CODEGRAPH_OPA_TIMEOUT", "opa_timeout_seconds"),
        description="Per-invocation timeout for OPA eval subprocesses.",
    )
    opengrep_timeout_seconds: float = Field(
        120.0,
        gt=0.0,
        validation_alias=AliasChoices("CODEGRAPH_OPENGREP_TIMEOUT", "opengrep_timeout_seconds"),
        description="Per-invocation timeout for OpenGrep taint-analysis subprocesses.",
    )
    opengrep_rules_dir: str = Field(
        "policy/opengrep",
        validation_alias=AliasChoices("CODEGRAPH_OPENGREP_RULES_DIR", "opengrep_rules_dir"),
        description="Directory of auto-discovered OpenGrep taint-mode rule files.",
    )
    detection_engines_enabled: bool = Field(
        True,
        validation_alias=AliasChoices("CODEGRAPH_DETECTION_ENGINES_ENABLED", "detection_engines_enabled"),
        description=(
            "Master switch for non-OPA detection engines. Disabling drops the rules they own, so "
            "coverage falls: intended for triage and for hermetic tests, not for normal operation."
        ),
    )
    policy_workers: int = Field(
        2, ge=1, le=32,
        description="Concurrent evidence/OPA workers per scan; at most twice this many tasks are submitted at once.",
    )
    ui_review_store_path: str = Field(
        "outputs/policy_ui_reviews/reviews.jsonl",
        description="Append-only JSONL store for UI triage/review records.",
    )
    java_parser_jar: Path = Field(
        PROJECT_ROOT / "tools/java-parser/target/codegraph-java-parser.jar",
        validation_alias=AliasChoices("JAVA_PARSER_JAR", "java_parser_jar"),
        description="Executable JDT parser fat jar used by the Python process-boundary adapter.",
    )
    java_parser_timeout_seconds: float = Field(
        30.0,
        gt=0.0,
        le=120.0,
        validation_alias=AliasChoices("JAVA_PARSER_TIMEOUT_SECONDS", "java_parser_timeout_seconds"),
        description="Per Java parser subprocess deadline in seconds.",
    )
    java_parser_heap_mb: int = Field(
        384,
        ge=128,
        le=2048,
        validation_alias=AliasChoices("JAVA_PARSER_HEAP_MB", "java_parser_heap_mb"),
        description="Maximum heap for each fresh Java parser subprocess.",
    )
    java_parser_max_concurrent_requests: int = Field(
        4,
        ge=1,
        le=32,
        validation_alias=AliasChoices("JAVA_PARSER_MAX_CONCURRENT_REQUESTS", "java_parser_max_concurrent_requests"),
        description="Process-local cap on active Java parser subprocess requests.",
    )
    ingestion_workers: int = Field(
        4,
        ge=1,
        le=32,
        validation_alias=AliasChoices("CODEGRAPH_INGESTION_WORKERS", "ingestion_workers"),
        description=(
            "Parser workers used while extracting a workspace. Each worker runs one JDT subprocess "
            "with its own heap, so raise it with java_parser_max_concurrent_requests and memory in mind."
        ),
    )
    ingestion_progress_every: int = Field(
        100,
        ge=1,
        description="Log extraction progress every N files so a long ingestion is observable.",
    )
    java_parser_queue_timeout_seconds: float = Field(
        5.0,
        gt=0.0,
        le=120.0,
        validation_alias=AliasChoices("JAVA_PARSER_QUEUE_TIMEOUT_SECONDS", "java_parser_queue_timeout_seconds"),
        description="Maximum queue wait for Java parser subprocess admission.",
    )
    java_parser_max_source_bytes: int = Field(
        4 * 1024 * 1024,
        ge=1 * 1024 * 1024,
        le=4 * 1024 * 1024,
        validation_alias=AliasChoices("JAVA_PARSER_MAX_SOURCE_BYTES", "java_parser_max_source_bytes"),
        description="Maximum source bytes accepted by the Java parser adapter.",
    )
    java_parser_max_output_bytes: int = Field(
        16 * 1024 * 1024,
        ge=1 * 1024 * 1024,
        le=16 * 1024 * 1024,
        validation_alias=AliasChoices("JAVA_PARSER_MAX_OUTPUT_BYTES", "java_parser_max_output_bytes"),
        description="Maximum stdout bytes accepted from the Java parser subprocess.",
    )
    java_parser_language_level: str = Field(
        "25",
        pattern=r"^(?:[89]|1[0-9]|2[0-5])$",
        validation_alias=AliasChoices("JAVA_PARSER_LANGUAGE_LEVEL", "java_parser_language_level"),
        description="Default JDT language level passed to the Java parser.",
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
    if configured == "":
        return None
    if configured:
        return configured
    default_env = PROJECT_ROOT / ".env"
    if default_env.is_file():
        return str(default_env)
    return None


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
