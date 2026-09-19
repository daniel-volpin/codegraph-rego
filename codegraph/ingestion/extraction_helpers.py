from __future__ import annotations

import hashlib
import os
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

from codegraph.ingestion.config_facts import collect_config_properties, find_project_root
from codegraph.ingestion.extraction_models import GRAPH_SCHEMA_VERSION, IngestionError
from codegraph.ingestion.models import ClassEntity, FieldEntity, MethodEntity
from codegraph.java.models import (
    FieldDeclarationDTO,
    MethodDeclarationDTO,
    ParsedJavaFileDTO,
    TypeDeclarationDTO,
)


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


def _collect_workspace_config(
    root_dir: str | None,
    workspace_id: str,
    revision_id: str,
) -> tuple[dict[str, Any], ...]:
    if not root_dir:
        return ()
    scan_root = find_project_root(root_dir) or Path(root_dir)
    declarations = collect_config_properties(scan_root)
    return tuple(
        {
            "config_key": declaration.key,
            "value": declaration.value,
            "source_file": declaration.source_file,
            "line": declaration.line,
            "workspace_id": workspace_id,
            "revision_id": revision_id,
            "property_key": f"{workspace_id}:{revision_id}:{declaration.source_file}:{declaration.line}",
        }
        for declaration in declarations
    )


def _normalize_source_roots(root_dir: str, source_roots: Sequence[str | os.PathLike[str]] | None) -> tuple[Path, ...]:
    roots = source_roots if source_roots is not None else (root_dir,)
    normalized = tuple(Path(root).resolve() for root in roots)
    missing = [str(root) for root in normalized if not root.is_dir()]
    if missing:
        raise IngestionError(f"Source root directories do not exist: {', '.join(missing)}")
    return normalized
