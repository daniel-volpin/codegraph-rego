"""AST Entity and Relationship Extraction for CodeGraph Ingestion."""

from __future__ import annotations

import logging
import os
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from codegraph.common.concurrency import bounded_futures
from codegraph.config import settings
from codegraph.ingestion.extraction_helpers import (
    _class_entity,
    _collect_workspace_config,
    _field_entity,
    _method_entity,
    _namespaced_key,
    _normalize_source_roots,
    _range_end_byte,
    _range_end_line,
    _range_start_byte,
    _range_start_line,
    _revision_id,
    _sha256_bytes,
    _type_display,
    _validate_parsed_generation,
    _workspace_id,
)
from codegraph.ingestion.extraction_models import (
    GRAPH_SCHEMA_VERSION,
    ExtractedCodeStructure,
    IngestionError,
    ProgressCallback,
    WorkspacePublication,
)
from codegraph.ingestion.models import ClassEntity, FieldEntity, MethodEntity
from codegraph.java.models import ParsedJavaFileDTO
from codegraph.java.service import parse_java_source

LOGGER = logging.getLogger(__name__)

__all__ = [
    "GRAPH_SCHEMA_VERSION",
    "ExtractedCodeStructure",
    "IngestionError",
    "ProgressCallback",
    "WorkspacePublication",
    "_class_entity",
    "_field_entity",
    "_method_entity",
    "_namespaced_key",
    "_parse_java_source",
    "_range_end_byte",
    "_range_end_line",
    "_range_start_byte",
    "_range_start_line",
    "_revision_id",
    "_sha256_bytes",
    "_type_display",
    "_workspace_id",
    "collect_code_structure",
    "extract_entities_from_parsed_files",
]


def _parse_java_source(*args: Any, **kwargs: Any) -> ParsedJavaFileDTO:
    return parse_java_source(*args, **kwargs)


def extract_entities_from_parsed_files(
    parsed_files: list[ParsedJavaFileDTO],
    *,
    workspace_id: str,
    revision_id: str,
    root_dir: str | None = None,
) -> ExtractedCodeStructure:
    classes: list[ClassEntity] = []
    fields: list[FieldEntity] = []
    methods: list[MethodEntity] = []
    nested: list[tuple[str, str]] = []
    extends: list[tuple[str, str, str]] = []
    implements: list[tuple[str, str, str]] = []
    calls: list[tuple[str, str, str]] = []
    call_evidence: list[dict[str, Any]] = []
    method_fields: list[tuple[str, str]] = []
    diagnostics: list[dict[str, Any]] = []
    binding_to_method_key: dict[str, str] = {}
    field_binding_to_key: dict[str, str] = {}
    type_binding_to_key: dict[str, str] = {}
    local_method_keys: set[str] = set()
    parser_backend, parser_version, adapter_version, classpath_fingerprint = _validate_parsed_generation(parsed_files)
    source_files: list[dict[str, Any]] = []

    for parsed in parsed_files:
        absolute_path = str(Path(root_dir, parsed.relative_path).resolve()) if root_dir else parsed.relative_path
        source_files.append(
            {
                "workspace_id": workspace_id,
                "revision_id": revision_id,
                "relative_path": parsed.relative_path,
                "file_path": absolute_path,
                "source_sha256": parsed.source_sha256,
                "source_byte_length": parsed.source_byte_length,
                "coverage": parsed.coverage,
                "parser_backend": parsed.provenance.backend,
                "parser_version": parsed.provenance.backend_version,
                "adapter_version": parsed.provenance.adapter_version,
                "diagnostics": [
                    {
                        "severity": diagnostic.severity,
                        "phase": diagnostic.phase,
                        "code": diagnostic.code,
                        "message": diagnostic.message,
                        "coverage_impact": diagnostic.coverage_impact,
                    }
                    for diagnostic in parsed.diagnostics
                ],
            }
        )
        for type_dto in parsed.types:
            entity = _class_entity(parsed, type_dto, workspace_id=workspace_id, revision_id=revision_id, absolute_path=absolute_path)
            classes.append(entity)
            if type_dto.binding_key and type_dto.binding_origin == "source":
                type_binding_to_key[type_dto.binding_key] = entity.type_key
            if entity.enclosing_type_key:
                nested.append((entity.type_key, entity.enclosing_type_key))
        for field_dto in parsed.fields:
            entity = _field_entity(parsed, field_dto, workspace_id=workspace_id, revision_id=revision_id, absolute_path=absolute_path)
            fields.append(entity)
            if field_dto.binding_key:
                field_binding_to_key[field_dto.binding_key] = entity.field_key
        for method_dto in parsed.methods:
            entity = _method_entity(parsed, method_dto, workspace_id=workspace_id, revision_id=revision_id, absolute_path=absolute_path)
            methods.append(entity)
            local_method_keys.add(entity.method_key)
            if method_dto.resolved_binding_key:
                binding_to_method_key[method_dto.resolved_binding_key] = entity.method_key
        diagnostics.extend(
            {
                "relative_path": parsed.relative_path,
                "severity": diagnostic.severity,
                "phase": diagnostic.phase,
                "code": diagnostic.code,
                "message": diagnostic.message,
                "coverage_impact": diagnostic.coverage_impact,
            }
            for diagnostic in parsed.diagnostics
        )

    type_key_by_source_key = {entity.type_key.rsplit("#", 1)[-1]: entity.type_key for entity in classes}
    for parsed in parsed_files:
        for type_dto in parsed.types:
            child_key = _namespaced_key(workspace_id, revision_id, parsed.relative_path, type_dto.source_key)
            if type_dto.superclass and type_dto.superclass.binding_origin == "source":
                parent_key = type_binding_to_key.get(type_dto.superclass.binding_key or "")
                if parent_key:
                    extends.append((child_key, parent_key, type_dto.superclass.resolution_status))
            for interface in type_dto.interfaces:
                parent_key = None
                if interface.binding_origin == "source":
                    parent_key = type_binding_to_key.get(interface.binding_key or "")
                if parent_key is None and interface.source:
                    parent_key = type_key_by_source_key.get(interface.source)
                if parent_key:
                    implements.append((child_key, parent_key, interface.resolution_status))

    for parsed in parsed_files:
        for method_dto in parsed.methods:
            caller_key = _namespaced_key(workspace_id, revision_id, parsed.relative_path, method_dto.source_key)
            for invocation in method_dto.invocations:
                target_key = None
                if invocation.target_method_source_key:
                    candidate_key = _namespaced_key(
                        workspace_id, revision_id, parsed.relative_path, invocation.target_method_source_key
                    )
                    if candidate_key in local_method_keys:
                        target_key = candidate_key
                if target_key is None and invocation.resolution_status == "resolved" and invocation.binding_origin == "source":
                    target_key = binding_to_method_key.get(invocation.resolved_binding_key or "")
                if target_key:
                    calls.append(
                        (
                            caller_key,
                            target_key,
                            _namespaced_key(workspace_id, revision_id, parsed.relative_path, invocation.source_key),
                        )
                    )
                    continue
                call_evidence.append(
                    {
                        "call_key": _namespaced_key(workspace_id, revision_id, parsed.relative_path, invocation.source_key),
                        "caller_key": caller_key,
                        "name": invocation.name,
                        "qualifier": invocation.qualifier_source,
                        "argument_count": invocation.argument_count,
                        "argument_sources": [
                            argument.source for argument in invocation.arguments if argument.source is not None
                        ],
                        "resolution_status": invocation.resolution_status,
                        "binding_origin": invocation.binding_origin,
                        "resolved_binding_key": invocation.resolved_binding_key,
                        "resolved_descriptor": invocation.resolved_descriptor,
                        "unresolved_reason": invocation.unresolved_reason,
                        "start_byte": _range_start_byte(invocation.invocation_range),
                        "end_byte": _range_end_byte(invocation.invocation_range),
                    }
                )
            for field_use in method_dto.field_uses:
                field_key = field_binding_to_key.get(field_use.field_binding_key or "")
                if field_key:
                    method_fields.append((caller_key, field_key))

    return ExtractedCodeStructure(
        workspace_id=workspace_id,
        revision_id=revision_id,
        parser_backend=parser_backend,
        parser_version=parser_version,
        adapter_version=adapter_version,
        source_fingerprint=_revision_id(parsed_files),
        classpath_fingerprint=classpath_fingerprint,
        source_files=tuple(source_files),
        classes=tuple(classes),
        methods=tuple(methods),
        fields=tuple(fields),
        nested_relations=tuple(dict.fromkeys(nested)),
        extends_relations=tuple(extends),
        implements_relations=tuple(implements),
        calls_relations=tuple(dict.fromkeys(calls)),
        call_evidence=tuple(call_evidence),
        config_properties=_collect_workspace_config(root_dir, workspace_id, revision_id),
        method_field_relations=tuple(dict.fromkeys(method_fields)),
        diagnostics=tuple(diagnostics),
    )


def collect_code_structure(
    root_dir: str,
    progress_callback: ProgressCallback | None = None,
    *,
    source_roots: Sequence[str | os.PathLike[str]] | None = None,
) -> ExtractedCodeStructure:
    parser_source_roots = _normalize_source_roots(root_dir, source_roots)
    java_files: list[str] = []
    for root, _, files in os.walk(root_dir):
        for file_name in files:
            if file_name.endswith(".java"):
                java_files.append(os.path.join(root, file_name))
    ordered_files = sorted(java_files)
    total = len(ordered_files) or 1

    def parse_one(file_path: str) -> ParsedJavaFileDTO:
        relative_path = os.path.relpath(file_path, root_dir).replace(os.sep, "/")
        source_bytes = Path(file_path).read_bytes()
        parsed = _parse_java_source(
            source_bytes,
            relative_path=relative_path,
            source_roots=parser_source_roots,
            classpath=(),
            resolve_bindings=True,
            language_level=None,
        )
        if parsed.source_sha256 != _sha256_bytes(source_bytes):
            raise IngestionError(f"Parser source hash mismatch for {relative_path}; refusing ingestion")
        return parsed

    parsed_files: list[ParsedJavaFileDTO] = [None] * len(ordered_files)  # type: ignore[list-item]
    completed = 0
    for index, future in bounded_futures(parse_one, ordered_files, max_workers=settings.ingestion_workers):
        parsed_files[index] = future.result()
        completed += 1
        if completed % settings.ingestion_progress_every == 0 or completed == len(ordered_files):
            LOGGER.info("Parsed %d/%d Java files", completed, len(ordered_files))
        if progress_callback:
            relative_path = os.path.relpath(ordered_files[index], root_dir).replace(os.sep, "/")
            progress_callback("parsing", f"Parsing {relative_path}", min(20.0 + 40.0 * completed / total, 60.0))
    revision_id = _revision_id(parsed_files)
    return extract_entities_from_parsed_files(
        parsed_files,
        workspace_id=_workspace_id(root_dir),
        revision_id=revision_id,
        root_dir=root_dir,
    )
