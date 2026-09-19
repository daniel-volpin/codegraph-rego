from __future__ import annotations

import ipaddress
from pathlib import Path

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings

from codegraph.config_models_llm import BaseLLMSettings

PROJECT_ROOT = Path(__file__).resolve().parents[1]

__all__ = ["BaseCoreSettings", "BaseJavaSettings", "BaseLLMSettings", "PROJECT_ROOT"]


class BaseCoreSettings(BaseSettings):
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
    upload_git_allowed_hosts: list[str] = Field(
        default_factory=lambda: ["github.com"],
        validation_alias=AliasChoices("UPLOAD_GIT_ALLOWED_HOSTS", "upload_git_allowed_hosts"),
        description="Hosts a repository may be cloned from. Analysed code is later compiled, so keep this narrow.",
    )
    upload_git_timeout_seconds: float = Field(
        300.0,
        gt=0.0,
        le=1800.0,
        validation_alias=AliasChoices("UPLOAD_GIT_TIMEOUT_SECONDS", "upload_git_timeout_seconds"),
        description="Deadline for a repository clone.",
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
        2,
        ge=1,
        le=32,
        description="Concurrent evidence/OPA workers per scan; at most twice this many tasks are submitted at once.",
    )
    ui_review_store_path: str = Field(
        "outputs/policy_ui_reviews/reviews.jsonl",
        description="Append-only JSONL store for UI triage/review records.",
    )

    @field_validator("backend_host")
    @classmethod
    def _validate_backend_host(cls, value: str) -> str:
        if value == "localhost":
            return value
        ipaddress.ip_address(value)
        return value


class BaseJavaSettings(BaseSettings):
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
