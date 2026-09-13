"""AST Entity and Relationship Extraction for CodeGraph Ingestion."""

from __future__ import annotations

import hashlib
import logging
import os
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from codegraph.common.concurrency import bounded_futures
from codegraph.config import settings
from codegraph.ingestion.models import ClassEntity, FieldEntity, MethodEntity
from codegraph.java.models import (
    FieldDeclarationDTO,
    MethodDeclarationDTO,
    ParsedJavaFileDTO,
    TypeDeclarationDTO,
)
from codegraph.java.service import parse_java_source

LOGGER = logging.getLogger(__name__)

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
    method_field_relations: tuple[tuple[str, str], ...] = ()
    diagnostics: tuple[dict[str, Any], ...] = ()


def _parse_java_source(*args, **kwargs) -> ParsedJavaFileDTO:
    return parse_java_source(*args, **kwargs)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _workspace_id(root_dir: str) -> str:
    return hashlib.sha256(str(Path(root_dir).resolve()).encode("utf-8")).hexdigest()[:16]


def _revision_id(parsed_files: Iterable[ParsedJavaFileDTO]) -> str:
    digest = hashlib.sha256()
    digest.update(GRAPH_SCHEMA_VERSION.encode("utf-8"))
    digest.update(b"\0")
    for parsed in sorted(parsed_files, key=lambda item: item.relative_path):
        provenance = parsed.provenance
        digest.update(parsed.relative_path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(parsed.source_sha256.encode("ascii"))
        digest.update(b"\0")
        digest.update(provenance.backend.encode("utf-8"))
        digest.update(b"\0")
        digest.update(provenance.backend_version.encode("utf-8"))
        digest.update(b"\0")
        digest.update(provenance.adapter_version.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(provenance.language_level or "").encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(provenance.classpath_fingerprint or "").encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest()


def _namespaced_key(workspace_id: str, revision_id: str, relative_path: str, source_key: str) -> str:
    return f"{workspace_id}@{revision_id}:{relative_path}#{source_key}"


def _range_start_line(dto_range) -> int | None:
    return dto_range.start_line if dto_range and dto_range.status == "verified" else None


def _range_end_line(dto_range) -> int | None:
    return dto_range.end_line if dto_range and dto_range.status == "verified" else None


def _range_start_byte(dto_range) -> int | None:
    return dto_range.start_byte if dto_range and dto_range.status == "verified" else None


def _range_end_byte(dto_range) -> int | None:
    return dto_range.end_byte if dto_range and dto_range.status == "verified" else None


def _type_display(type_ref) -> str | None:
    if type_ref is None:
        return None
    suffix = "[]" * int(type_ref.array_dimensions or 0)
    if type_ref.varargs:
        suffix = "..." + suffix
    return (type_ref.qualified_name or type_ref.source or type_ref.descriptor) + suffix if (
        type_ref.qualified_name or type_ref.source or type_ref.descriptor
    ) else None


def _field_entity(
    parsed: ParsedJavaFileDTO,
    field_dto: FieldDeclarationDTO,
    *,
    workspace_id: str,
    revision_id: str,
    absolute_path: str,
) -> FieldEntity:
    return FieldEntity(
        field_key=_namespaced_key(workspace_id, revision_id, parsed.relative_path, field_dto.source_key),
        declaring_type_key=_namespaced_key(workspace_id, revision_id, parsed.relative_path, field_dto.declaring_type_source_key),
        workspace_id=workspace_id,
        revision_id=revision_id,
        relative_path=parsed.relative_path,
        class_fqn=None,
        name=field_dto.name,
        type=_type_display(field_dto.type),
        modifiers=list(field_dto.modifiers),
        annotations=list(field_dto.annotation_names),
        file_path=absolute_path,
        start_line=_range_start_line(field_dto.declaration_range),
        end_line=_range_end_line(field_dto.declaration_range),
        start_byte=_range_start_byte(field_dto.declaration_range),
        end_byte=_range_end_byte(field_dto.declaration_range),
        source_sha256=parsed.source_sha256,
        parser_backend=parsed.provenance.backend,
        parser_version=parsed.provenance.backend_version,
        adapter_version=parsed.provenance.adapter_version,
        resolution_status=field_dto.resolution_status,
        binding_origin=field_dto.binding_origin,
        binding_key=field_dto.binding_key,
        range_status=field_dto.declaration_range.status,
    )


def _class_entity(
    parsed: ParsedJavaFileDTO,
    type_dto: TypeDeclarationDTO,
    *,
    workspace_id: str,
    revision_id: str,
    absolute_path: str,
) -> ClassEntity:
    return ClassEntity(
        type_key=_namespaced_key(workspace_id, revision_id, parsed.relative_path, type_dto.source_key),
        workspace_id=workspace_id,
        revision_id=revision_id,
        relative_path=parsed.relative_path,
        fqn=type_dto.qualified_name,
        binary_name=type_dto.binary_name,
        name=type_dto.name,
        kind=type_dto.kind,
        nesting_path=list(type_dto.nesting_path),
        enclosing_type_key=(
            _namespaced_key(workspace_id, revision_id, parsed.relative_path, type_dto.enclosing_type_source_key)
            if type_dto.enclosing_type_source_key
            else None
        ),
        modifiers=list(type_dto.modifiers),
        annotations=list(type_dto.annotation_names),
        file_path=absolute_path,
        start_line=_range_start_line(type_dto.declaration_range),
        end_line=_range_end_line(type_dto.declaration_range),
        start_byte=_range_start_byte(type_dto.declaration_range),
        end_byte=_range_end_byte(type_dto.declaration_range),
        source_sha256=parsed.source_sha256,
        parser_backend=parsed.provenance.backend,
        parser_version=parsed.provenance.backend_version,
        adapter_version=parsed.provenance.adapter_version,
        resolution_status=type_dto.resolution_status,
        binding_origin=type_dto.binding_origin,
        binding_key=type_dto.binding_key,
        range_status=type_dto.declaration_range.status,
    )


def _method_entity(
    parsed: ParsedJavaFileDTO,
    method_dto: MethodDeclarationDTO,
    *,
    workspace_id: str,
    revision_id: str,
    absolute_path: str,
) -> MethodEntity:
    return MethodEntity(
        method_key=_namespaced_key(workspace_id, revision_id, parsed.relative_path, method_dto.source_key),
        declaring_type_key=_namespaced_key(
            workspace_id, revision_id, parsed.relative_path, method_dto.declaring_type_source_key
        ),
        workspace_id=workspace_id,
        revision_id=revision_id,
        relative_path=parsed.relative_path,
        class_fqn=method_dto.declaring_type_qualified_name,
        signature=method_dto.display_signature,
        full_signature=method_dto.full_signature,
        name=method_dto.name,
        params=[f"{_type_display(param.type) or ''} {param.name}".strip() for param in method_dto.parameters],
        annotations=list(method_dto.annotation_names),
        return_type=_type_display(method_dto.return_type),
        modifiers=list(method_dto.modifiers),
        file_path=absolute_path,
        calls=[],
        uses=[],
        start_line=_range_start_line(method_dto.declaration_range),
        end_line=_range_end_line(method_dto.declaration_range),
        start_byte=_range_start_byte(method_dto.declaration_range),
        end_byte=_range_end_byte(method_dto.declaration_range),
        source_sha256=parsed.source_sha256,
        parser_backend=parsed.provenance.backend,
        parser_version=parsed.provenance.backend_version,
        adapter_version=parsed.provenance.adapter_version,
        language_level=parsed.provenance.language_level,
        resolution_status=method_dto.resolution_status,
        binding_origin=method_dto.binding_origin,
        resolved_binding_key=method_dto.resolved_binding_key,
        resolved_descriptor=method_dto.resolved_descriptor,
        range_status=method_dto.declaration_range.status,
    )


def _parser_generation_key(parsed: ParsedJavaFileDTO) -> tuple[str, str, str, str | None, str | None]:
    provenance = parsed.provenance
    return (
        provenance.backend,
        provenance.backend_version,
        provenance.adapter_version,
        provenance.language_level,
        provenance.classpath_fingerprint,
    )


def _validate_parsed_generation(parsed_files: list[ParsedJavaFileDTO]) -> tuple[str, str, str, str | None]:
    if not parsed_files:
        raise IngestionError("No Java parser results were produced; refusing to publish an empty graph revision.")
    failed = [parsed.relative_path for parsed in parsed_files if parsed.coverage == "failed"]
    if failed:
        raise IngestionError(f"JDT failed parser coverage for {', '.join(sorted(failed))}; refusing graph publication.")
    generation_keys = {_parser_generation_key(parsed) for parsed in parsed_files}
    if len(generation_keys) != 1:
        raise IngestionError("JDT mixed parser generation detected; refusing graph publication.")
    backend, backend_version, adapter_version, _language_level, classpath_fingerprint = next(iter(generation_keys))
    return backend, backend_version, adapter_version, classpath_fingerprint


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
        method_field_relations=tuple(dict.fromkeys(method_fields)),
        diagnostics=tuple(diagnostics),
    )


def _normalize_source_roots(root_dir: str, source_roots: Sequence[str | os.PathLike[str]] | None) -> tuple[Path, ...]:
    roots = source_roots if source_roots is not None else (root_dir,)
    normalized = tuple(Path(root).resolve() for root in roots)
    missing = [str(root) for root in normalized if not root.is_dir()]
    if missing:
        raise IngestionError(f"Source root directories do not exist: {', '.join(missing)}")
    return normalized


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

    # Each parse is an independent subprocess; downstream ordering is by
    # relative_path, so completion order cannot affect the revision id.
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
