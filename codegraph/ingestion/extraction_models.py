from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from codegraph.ingestion.models import ClassEntity, FieldEntity, MethodEntity

GRAPH_SCHEMA_VERSION = "codegraph-jdt/v1"
ProgressCallback = Callable[[str, str, float], None]


class IngestionError(RuntimeError):
    """Raised when ingestion cannot complete successfully."""


@dataclass(frozen=True)
class WorkspacePublication:
    workspace_id: str
    revision_id: str
    previous_revision_id: str | None


@dataclass(frozen=True)
class ExtractedCodeStructure:
    workspace_id: str
    revision_id: str
    parser_backend: str
    parser_version: str
    adapter_version: str
    source_fingerprint: str
    classpath_fingerprint: str | None
    source_files: tuple[dict[str, Any], ...] = ()
    classes: tuple[ClassEntity, ...] = ()
    methods: tuple[MethodEntity, ...] = ()
    fields: tuple[FieldEntity, ...] = ()
    nested_relations: tuple[tuple[str, str], ...] = ()
    extends_relations: tuple[tuple[str, str, str], ...] = ()
    implements_relations: tuple[tuple[str, str, str], ...] = ()
    calls_relations: tuple[tuple[str, str, str], ...] = ()
    call_evidence: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    config_properties: tuple[dict[str, Any], ...] = field(default_factory=tuple)
    method_field_relations: tuple[tuple[str, str], ...] = ()
    diagnostics: tuple[dict[str, Any], ...] = ()
