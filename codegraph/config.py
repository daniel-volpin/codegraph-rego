from functools import lru_cache
import os
import warnings
from typing import Any, Optional
from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
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
    neo4j_pass: Optional[str] = Field(
        None,
        validation_alias=AliasChoices("NEO4J_PASS", "neo4j_pass"),
        description="Neo4j password",
    )
    llm_provider: str = Field(
        "openai",
        validation_alias=AliasChoices("LLM_PROVIDER", "llm_provider"),
        description="LLM provider",
    )
    llm_model: str = Field(
        "gpt-4o-mini",
        validation_alias=AliasChoices("LLM_MODEL", "llm_model"),
        description="LLM model",
    )
    llm_api_base: Optional[str] = Field(
        None,
        validation_alias=AliasChoices("LLM_API_BASE", "llm_api_base"),
        description="LLM API base",
    )
    llm_api_key: Optional[str] = Field(
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
    llm_max_tokens_explanation: Optional[int] = Field(
        512,
        gt=0,
        validation_alias=AliasChoices("LLM_MAX_TOKENS_EXPLANATION", "llm_max_tokens_explanation"),
        description="Maximum tokens to generate for explanation calls.",
    )
    llm_max_tokens_remediation: Optional[int] = Field(
        1024,
        gt=0,
        validation_alias=AliasChoices("LLM_MAX_TOKENS_REMEDIATION", "llm_max_tokens_remediation"),
        description="Maximum tokens to generate for remediation calls.",
    )
    llm_model_ttl_seconds: Optional[int] = Field(
        None,
        gt=0,
        validation_alias=AliasChoices("LLM_MODEL_TTL_SECONDS", "llm_model_ttl_seconds"),
        description="Optional LM Studio model TTL (seconds) for explanation/default requests.",
    )
    remediation_llm_model: Optional[str] = Field(
        None,
        validation_alias=AliasChoices("REMEDIATION_LLM_MODEL", "remediation_llm_model"),
        description="Optional model override for remediation generation.",
    )
    remediation_llm_max_tokens: Optional[int] = Field(
        None,
        gt=0,
        validation_alias=AliasChoices("REMEDIATION_LLM_MAX_TOKENS", "remediation_llm_max_tokens"),
        description="Optional token cap override for remediation generation.",
    )
    remediation_llm_temperature: Optional[float] = Field(
        None,
        ge=0.0,
        le=2.0,
        validation_alias=AliasChoices("REMEDIATION_LLM_TEMPERATURE", "remediation_llm_temperature"),
        description="Optional temperature override for remediation generation.",
    )
    remediation_llm_model_ttl_seconds: Optional[int] = Field(
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
    ui_review_store_path: str = Field(
        "outputs/policy_ui_reviews/reviews.jsonl",
        description="Append-only JSONL store for UI triage/review records.",
    )

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def clear_settings_cache() -> None:
    get_settings.cache_clear()


def validate_runtime_settings(candidate: Optional[Settings] = None) -> Settings:
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

# Backward-compatible exports are resolved lazily to avoid import-time validation failures.
_LEGACY_EXPORTS = {
    "CORS_ALLOWED_ORIGINS": "cors_allowed_origins",
    "INDEX_DIR": "index_dir",
    "FAISS_INDEX_PATH": "faiss_index_path",
    "SIGNATURE_MAP_PATH": "signature_map_path",
    "SIGNATURE_MAP_PATH_FULL": "signature_map_path_full",
    "EMBEDDING_METADATA_PATH": "embedding_metadata_path",
    "EMBEDDING_CACHE_PATH": "embedding_cache_path",
    "EMBEDDING_MODEL_NAME": "embedding_model_name",
    "UPLOAD_DIR": "upload_dir",
    "JAVA_ROOT_DIR": "java_root_dir",
    "UPLOAD_MAX_ARCHIVE_SIZE_BYTES": "upload_max_archive_size_bytes",
    "UPLOAD_MAX_MEMBER_SIZE_BYTES": "upload_max_member_size_bytes",
    "UPLOAD_MAX_EXTRACTED_SIZE_BYTES": "upload_max_extracted_size_bytes",
    "UPLOAD_MAX_ARCHIVE_ENTRIES": "upload_max_archive_entries",
    "UPLOAD_MAX_COMPRESSION_RATIO": "upload_max_compression_ratio",
    "NEO4J_URI": "neo4j_uri",
    "NEO4J_USER": "neo4j_user",
    "NEO4J_PASS": "neo4j_pass",
    "LLM_PROVIDER": "llm_provider",
    "LLM_MODEL": "llm_model",
    "LLM_API_BASE": "llm_api_base",
    "LLM_API_KEY": "llm_api_key",
    "LLM_TEMPERATURE": "llm_temperature",
    "LLM_ENABLE_THINKING": "llm_enable_thinking",
    "LLM_MAX_TOKENS_EXPLANATION": "llm_max_tokens_explanation",
    "LLM_MAX_TOKENS_REMEDIATION": "llm_max_tokens_remediation",
    "LLM_MODEL_TTL_SECONDS": "llm_model_ttl_seconds",
    "REMEDIATION_LLM_MODEL": "remediation_llm_model",
    "REMEDIATION_LLM_MAX_TOKENS": "remediation_llm_max_tokens",
    "REMEDIATION_LLM_TEMPERATURE": "remediation_llm_temperature",
    "REMEDIATION_LLM_MODEL_TTL_SECONDS": "remediation_llm_model_ttl_seconds",
    "LLM_CONCURRENCY": "llm_concurrency",
    "REMEDIATION_RAW_CAPTURE_ENABLED": "remediation_raw_capture_enabled",
    "REMEDIATION_CONFIDENCE_GATE_ENABLED": "remediation_confidence_gate_enabled",
    "REMEDIATION_CONFIDENCE_THRESHOLD_APPLY": "remediation_confidence_threshold_apply",
    "REMEDIATION_CONFIDENCE_THRESHOLD_REVIEW": "remediation_confidence_threshold_review",
    "REMEDIATION_CONFIDENCE_TEMPERATURE": "remediation_confidence_temperature",
    "UI_REVIEW_STORE_PATH": "ui_review_store_path",
}
_WARNED_LEGACY_EXPORTS: set[str] = set()
_WARN_LEGACY_EXPORTS = os.getenv("CODEGRAPH_WARN_LEGACY_CONFIG_EXPORTS", "0") == "1"


def __getattr__(name: str) -> Any:
    field_name = _LEGACY_EXPORTS.get(name)
    if field_name is not None:
        if _WARN_LEGACY_EXPORTS and name not in _WARNED_LEGACY_EXPORTS:
            warnings.warn(
                f"{name} is deprecated; use get_settings().{field_name} or settings.{field_name} instead.",
                DeprecationWarning,
                stacklevel=2,
            )
            _WARNED_LEGACY_EXPORTS.add(name)
        return getattr(get_settings(), field_name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
