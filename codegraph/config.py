from typing import Optional
from pydantic import BaseSettings, Field


class Settings(BaseSettings):
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
    upload_max_archive_size_bytes: int = Field(100 * 1024 * 1024, description="Maximum uploaded ZIP size")
    upload_max_member_size_bytes: int = Field(50 * 1024 * 1024, description="Maximum uncompressed ZIP member size")
    upload_max_extracted_size_bytes: int = Field(
        500 * 1024 * 1024, description="Maximum total uncompressed bytes extracted from a ZIP"
    )
    upload_max_archive_entries: int = Field(10_000, description="Maximum number of entries allowed in a ZIP")
    upload_max_compression_ratio: float = Field(100.0, description="Maximum allowed ZIP compression ratio per member")
    neo4j_uri: str = Field("bolt://localhost:7687", description="Neo4j URI")
    neo4j_user: str = Field("neo4j", description="Neo4j user")
    neo4j_pass: str = Field(..., description="Neo4j password")
    llm_provider: str = Field("openai", description="LLM provider")
    llm_model: str = Field("gpt-4o-mini", description="LLM model")
    llm_api_base: str = Field(None, description="LLM API base")
    llm_api_key: str = Field(None, description="LLM API key")
    llm_temperature: float = Field(0.2, description="LLM temperature")
    llm_enable_thinking: bool = Field(
        True,
        description=(
            "Whether to allow LLM chain-of-thought <think> blocks. "
            "Set to false to suppress thinking on models that support it (Qwen3, DeepSeek)."
        ),
    )
    llm_max_tokens_explanation: Optional[int] = Field(
        512,
        description="Maximum tokens to generate for explanation calls.",
    )
    llm_max_tokens_remediation: Optional[int] = Field(
        1024,
        description="Maximum tokens to generate for remediation calls.",
    )
    llm_model_ttl_seconds: Optional[int] = Field(
        None,
        description="Optional LM Studio model TTL (seconds) for explanation/default requests.",
    )
    remediation_llm_model: Optional[str] = Field(
        None,
        description="Optional model override for remediation generation.",
    )
    remediation_llm_max_tokens: Optional[int] = Field(
        None,
        description="Optional token cap override for remediation generation.",
    )
    remediation_llm_temperature: Optional[float] = Field(
        None,
        description="Optional temperature override for remediation generation.",
    )
    remediation_llm_model_ttl_seconds: Optional[int] = Field(
        None,
        description="Optional LM Studio model TTL (seconds) for remediation requests.",
    )
    llm_concurrency: int = Field(
        2,
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
    ui_review_store_path: str = Field(
        "outputs/policy_ui_reviews/reviews.jsonl",
        description="Append-only JSONL store for UI triage/review records.",
    )

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        fields = {
            "index_dir": {"env": "INDEX_DIR"},
            "faiss_index_path": {"env": "FAISS_INDEX_PATH"},
            "signature_map_path": {"env": "SIGNATURE_MAP_PATH"},
            "signature_map_path_full": {"env": "SIGNATURE_MAP_PATH_FULL"},
            "embedding_metadata_path": {"env": "EMBEDDING_METADATA_PATH"},
            "embedding_cache_path": {"env": "EMBEDDING_CACHE_PATH"},
            "embedding_model_name": {"env": "EMBEDDING_MODEL_NAME"},
            "upload_dir": {"env": "UPLOAD_DIR"},
            "java_root_dir": {"env": "JAVA_ROOT_DIR"},
            "upload_max_archive_size_bytes": {"env": "UPLOAD_MAX_ARCHIVE_SIZE_BYTES"},
            "upload_max_member_size_bytes": {"env": "UPLOAD_MAX_MEMBER_SIZE_BYTES"},
            "upload_max_extracted_size_bytes": {"env": "UPLOAD_MAX_EXTRACTED_SIZE_BYTES"},
            "upload_max_archive_entries": {"env": "UPLOAD_MAX_ARCHIVE_ENTRIES"},
            "upload_max_compression_ratio": {"env": "UPLOAD_MAX_COMPRESSION_RATIO"},
            "neo4j_uri": {"env": "NEO4J_URI"},
            "neo4j_user": {"env": "NEO4J_USER"},
            "neo4j_pass": {"env": "NEO4J_PASS"},
            "llm_provider": {"env": "LLM_PROVIDER"},
            "llm_model": {"env": "LLM_MODEL"},
            "llm_api_base": {"env": "LLM_API_BASE"},
            "llm_api_key": {"env": "LLM_API_KEY"},
            "llm_temperature": {"env": "LLM_TEMPERATURE"},
            "llm_enable_thinking": {"env": "LLM_ENABLE_THINKING"},
            "llm_max_tokens_explanation": {"env": "LLM_MAX_TOKENS_EXPLANATION"},
            "llm_max_tokens_remediation": {"env": "LLM_MAX_TOKENS_REMEDIATION"},
            "llm_model_ttl_seconds": {"env": "LLM_MODEL_TTL_SECONDS"},
            "remediation_llm_model": {"env": "REMEDIATION_LLM_MODEL"},
            "remediation_llm_max_tokens": {"env": "REMEDIATION_LLM_MAX_TOKENS"},
            "remediation_llm_temperature": {"env": "REMEDIATION_LLM_TEMPERATURE"},
            "remediation_llm_model_ttl_seconds": {"env": "REMEDIATION_LLM_MODEL_TTL_SECONDS"},
            "llm_concurrency": {"env": "LLM_CONCURRENCY"},
            "remediation_raw_capture_enabled": {"env": "REMEDIATION_RAW_CAPTURE_ENABLED"},
            "ui_review_store_path": {"env": "UI_REVIEW_STORE_PATH"},
        }


settings = Settings()

# For backward compatibility, expose old variable names
INDEX_DIR = settings.index_dir
FAISS_INDEX_PATH = settings.faiss_index_path
SIGNATURE_MAP_PATH = settings.signature_map_path
SIGNATURE_MAP_PATH_FULL = settings.signature_map_path_full
EMBEDDING_METADATA_PATH = settings.embedding_metadata_path
EMBEDDING_CACHE_PATH = settings.embedding_cache_path
EMBEDDING_MODEL_NAME = settings.embedding_model_name
UPLOAD_DIR = settings.upload_dir
JAVA_ROOT_DIR = settings.java_root_dir
UPLOAD_MAX_ARCHIVE_SIZE_BYTES = settings.upload_max_archive_size_bytes
UPLOAD_MAX_MEMBER_SIZE_BYTES = settings.upload_max_member_size_bytes
UPLOAD_MAX_EXTRACTED_SIZE_BYTES = settings.upload_max_extracted_size_bytes
UPLOAD_MAX_ARCHIVE_ENTRIES = settings.upload_max_archive_entries
UPLOAD_MAX_COMPRESSION_RATIO = settings.upload_max_compression_ratio
NEO4J_URI = settings.neo4j_uri
NEO4J_USER = settings.neo4j_user
NEO4J_PASS = settings.neo4j_pass
LLM_PROVIDER = settings.llm_provider
LLM_MODEL = settings.llm_model
LLM_API_BASE = settings.llm_api_base
LLM_API_KEY = settings.llm_api_key
LLM_TEMPERATURE = settings.llm_temperature
LLM_ENABLE_THINKING = settings.llm_enable_thinking
LLM_MAX_TOKENS_EXPLANATION = settings.llm_max_tokens_explanation
LLM_MAX_TOKENS_REMEDIATION = settings.llm_max_tokens_remediation
LLM_MODEL_TTL_SECONDS = settings.llm_model_ttl_seconds
REMEDIATION_LLM_MODEL = settings.remediation_llm_model
REMEDIATION_LLM_MAX_TOKENS = settings.remediation_llm_max_tokens
REMEDIATION_LLM_TEMPERATURE = settings.remediation_llm_temperature
REMEDIATION_LLM_MODEL_TTL_SECONDS = settings.remediation_llm_model_ttl_seconds
LLM_CONCURRENCY = settings.llm_concurrency
REMEDIATION_RAW_CAPTURE_ENABLED = settings.remediation_raw_capture_enabled
UI_REVIEW_STORE_PATH = settings.ui_review_store_path
