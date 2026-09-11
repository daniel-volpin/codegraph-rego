from __future__ import annotations

import hashlib
import logging
import os
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from importlib import import_module
from pathlib import Path
from typing import Any

from neo4j import GraphDatabase

from codegraph.config import settings
from codegraph.db import ensure_constraints
from codegraph.ingestion.models import ClassEntity, FieldEntity, MethodEntity
from codegraph.java.models import FieldDeclarationDTO, MethodDeclarationDTO, ParsedJavaFileDTO, TypeDeclarationDTO

LOGGER = logging.getLogger(__name__)


class IngestionError(RuntimeError):
    """Raised when ingestion cannot complete successfully."""


ProgressCallback = Callable[[str, str, float], None]
GRAPH_SCHEMA_VERSION = "codegraph-jdt/v1"


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
    try:
        service = import_module("codegraph.java.service")
    except ModuleNotFoundError as exc:
        raise IngestionError("Java parser service is unavailable; rebuild/provision the JDT parser adapter.") from exc
    return service.parse_java_source(*args, **kwargs)


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
    parsed_files: list[ParsedJavaFileDTO] = []
    for index, file_path in enumerate(sorted(java_files), start=1):
        relative_path = os.path.relpath(file_path, root_dir).replace(os.sep, "/")
        if progress_callback:
            progress_callback("parsing", f"Parsing {relative_path}", min(20.0 + 40.0 * index / (len(java_files) or 1), 60.0))
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
        parsed_files.append(parsed)
    revision_id = _revision_id(parsed_files)
    return extract_entities_from_parsed_files(
        parsed_files,
        workspace_id=_workspace_id(root_dir),
        revision_id=revision_id,
        root_dir=root_dir,
    )


def _chunked(values, size: int):
    for index in range(0, len(values), size):
        yield values[index : index + size]


def create_workspace_revision(tx, structure: ExtractedCodeStructure) -> None:
    tx.run(
        """
        MERGE (wr:WorkspaceRevision {workspace_id: $workspace_id, revision_id: $revision_id})
        ON CREATE SET wr.status = 'staged', wr.active = false
        SET wr.schema_version = $schema_version,
            wr.parser_backend = $parser_backend,
            wr.parser_version = $parser_version,
            wr.adapter_version = $adapter_version,
            wr.source_fingerprint = $source_fingerprint,
            wr.classpath_fingerprint = $classpath_fingerprint
        """,
        workspace_id=structure.workspace_id,
        revision_id=structure.revision_id,
        schema_version=GRAPH_SCHEMA_VERSION,
        parser_backend=structure.parser_backend,
        parser_version=structure.parser_version,
        adapter_version=structure.adapter_version,
        source_fingerprint=structure.source_fingerprint,
        classpath_fingerprint=structure.classpath_fingerprint,
    )


def create_source_file_batch(tx, source_files: tuple[dict[str, Any], ...]) -> None:
    tx.run(
        """
        UNWIND $source_files AS item
        MATCH (wr:WorkspaceRevision {workspace_id: item.workspace_id, revision_id: item.revision_id})
        MERGE (sf:SourceFile {workspace_id: item.workspace_id, revision_id: item.revision_id, relative_path: item.relative_path})
        SET sf.file_path = item.file_path,
            sf.source_sha256 = item.source_sha256,
            sf.source_byte_length = item.source_byte_length,
            sf.coverage = item.coverage,
            sf.parser_backend = item.parser_backend,
            sf.parser_version = item.parser_version,
            sf.adapter_version = item.adapter_version,
            sf.diagnostics = item.diagnostics
        MERGE (wr)-[:HAS_FILE]->(sf)
        """,
        source_files=list(source_files),
    )


def create_class_batch(tx, classes: tuple[ClassEntity, ...]) -> None:
    tx.run(
        """
        UNWIND $classes AS item
        MATCH (wr:WorkspaceRevision {workspace_id: item.workspace_id, revision_id: item.revision_id})
        MERGE (sf:SourceFile {workspace_id: item.workspace_id, revision_id: item.revision_id, relative_path: item.relative_path})
        MERGE (cls:Class {type_key: item.type_key})
        SET cls.fqn = item.fqn,
            cls.binary_name = item.binary_name,
            cls.name = item.name,
            cls.kind = item.kind,
            cls.nesting_path = item.nesting_path,
            cls.modifiers = item.modifiers,
            cls.annotations = item.annotations,
            cls.file_path = item.file_path,
            cls.relative_path = item.relative_path,
            cls.workspace_id = item.workspace_id,
            cls.revision_id = item.revision_id,
            cls.start_line = item.start_line,
            cls.end_line = item.end_line,
            cls.start_byte = item.start_byte,
            cls.end_byte = item.end_byte,
            cls.source_sha256 = item.source_sha256,
            cls.parser_backend = item.parser_backend,
            cls.parser_version = item.parser_version,
            cls.adapter_version = item.adapter_version,
            cls.resolution_status = item.resolution_status,
            cls.binding_origin = item.binding_origin,
            cls.binding_key = item.binding_key,
            cls.range_status = item.range_status
        MERGE (wr)-[:HAS_FILE]->(sf)
        MERGE (sf)-[:DECLARES_TYPE]->(cls)
        """,
        classes=[item.model_dump() for item in classes],
    )


def create_method_batch(tx, methods: tuple[MethodEntity, ...]) -> None:
    tx.run(
        """
        UNWIND $methods AS item
        MATCH (cls:Class {type_key: item.declaring_type_key})
        MERGE (m:Method {method_key: item.method_key})
        SET m.signature = item.signature,
            m.full_signature = item.full_signature,
            m.name = item.name,
            m.params = item.params,
            m.annotations = item.annotations,
            m.return_type = item.return_type,
            m.modifiers = item.modifiers,
            m.file_path = item.file_path,
            m.relative_path = item.relative_path,
            m.workspace_id = item.workspace_id,
            m.revision_id = item.revision_id,
            m.declaring_type_key = item.declaring_type_key,
            m.class_fqn = item.class_fqn,
            m.start_line = item.start_line,
            m.end_line = item.end_line,
            m.start_byte = item.start_byte,
            m.end_byte = item.end_byte,
            m.source_sha256 = item.source_sha256,
            m.parser_backend = item.parser_backend,
            m.parser_version = item.parser_version,
            m.adapter_version = item.adapter_version,
            m.language_level = item.language_level,
            m.resolution_status = item.resolution_status,
            m.binding_origin = item.binding_origin,
            m.resolved_binding_key = item.resolved_binding_key,
            m.resolved_descriptor = item.resolved_descriptor,
            m.range_status = item.range_status
        MERGE (cls)-[:DECLARES]->(m)
        """,
        methods=[item.model_dump() for item in methods],
    )


def create_field_batch(tx, fields: tuple[FieldEntity, ...]) -> None:
    tx.run(
        """
        UNWIND $fields AS item
        MATCH (cls:Class {type_key: item.declaring_type_key})
        MERGE (f:Field {field_key: item.field_key})
        SET f.name = item.name,
            f.type = item.type,
            f.modifiers = item.modifiers,
            f.annotations = item.annotations,
            f.file_path = item.file_path,
            f.relative_path = item.relative_path,
            f.workspace_id = item.workspace_id,
            f.revision_id = item.revision_id,
            f.declaring_type_key = item.declaring_type_key,
            f.class_fqn = item.class_fqn,
            f.start_line = item.start_line,
            f.end_line = item.end_line,
            f.start_byte = item.start_byte,
            f.end_byte = item.end_byte,
            f.source_sha256 = item.source_sha256,
            f.parser_backend = item.parser_backend,
            f.parser_version = item.parser_version,
            f.adapter_version = item.adapter_version,
            f.resolution_status = item.resolution_status,
            f.binding_origin = item.binding_origin,
            f.binding_key = item.binding_key,
            f.range_status = item.range_status
        MERGE (cls)-[:DECLARES_FIELD]->(f)
        """,
        fields=[item.model_dump() for item in fields],
    )


def link_nested_classes_batch(tx, relations: tuple[tuple[str, str], ...]) -> None:
    tx.run(
        """
        UNWIND $relations AS rel
        MATCH (child:Class {type_key: rel[0]})
        MATCH (parent:Class {type_key: rel[1]})
        MERGE (child)-[:NESTED_IN]->(parent)
        """,
        relations=list(relations),
    )


def link_extends_classes_batch(tx, relations: tuple[tuple[str, str, str], ...]) -> None:
    tx.run(
        """
        UNWIND $relations AS rel
        MATCH (child:Class {type_key: rel[0]})
        MATCH (parent:Class {type_key: rel[1]})
        MERGE (child)-[r:EXTENDS]->(parent)
        SET r.resolution_status = rel[2]
        """,
        relations=list(relations),
    )


def link_implements_classes_batch(tx, relations: tuple[tuple[str, str, str], ...]) -> None:
    tx.run(
        """
        UNWIND $relations AS rel
        MATCH (cls:Class {type_key: rel[0]})
        MATCH (iface:Class {type_key: rel[1]})
        MERGE (cls)-[r:IMPLEMENTS]->(iface)
        SET r.resolution_status = rel[2]
        """,
        relations=list(relations),
    )


def link_calls_batch(tx, relations: tuple[tuple[str, str, str], ...]) -> None:
    tx.run(
        """
        UNWIND $relations AS rel
        MATCH (caller:Method {method_key: rel[0]})
        MATCH (callee:Method {method_key: rel[1]})
        MERGE (caller)-[r:CALLS {call_key: rel[2]}]->(callee)
        """,
        relations=list(relations),
    )


def create_call_evidence_batch(tx, call_evidence: tuple[dict[str, Any], ...]) -> None:
    tx.run(
        """
        UNWIND $calls AS item
        MATCH (caller:Method {method_key: item.caller_key})
        MERGE (call:CallEvidence {call_key: item.call_key})
        SET call.name = item.name,
            call.qualifier = item.qualifier,
            call.argument_count = item.argument_count,
            call.resolution_status = item.resolution_status,
            call.binding_origin = item.binding_origin,
            call.resolved_binding_key = item.resolved_binding_key,
            call.resolved_descriptor = item.resolved_descriptor,
            call.unresolved_reason = item.unresolved_reason,
            call.start_byte = item.start_byte,
            call.end_byte = item.end_byte
        MERGE (caller)-[:HAS_CALL]->(call)
        """,
        calls=list(call_evidence),
    )


def link_method_field_use_batch(tx, relations: tuple[tuple[str, str], ...]) -> None:
    tx.run(
        """
        UNWIND $relations AS rel
        MATCH (m:Method {method_key: rel[0]})
        MATCH (f:Field {field_key: rel[1]})
        MERGE (m)-[:USES]->(f)
        """,
        relations=list(relations),
    )


def publish_workspace_revision(tx, structure: ExtractedCodeStructure) -> WorkspacePublication:
    record = tx.run(
        """
        MERGE (aw:ActiveWorkspace {workspace_id: $workspace_id})
        SET aw.publication_version = coalesce(aw.publication_version, 0) + 1
        WITH aw
        MATCH (wr:WorkspaceRevision {workspace_id: $workspace_id, revision_id: $revision_id})
        OPTIONAL MATCH (aw)-[old:ACTIVE_REVISION]->(previous:WorkspaceRevision)
        WITH aw, wr, collect(old) AS old_links, collect(previous.revision_id) AS previous_revisions
        FOREACH (old IN old_links | DELETE old)
        SET wr.status = 'active',
            wr.active = true,
            wr.published_at = datetime()
        MERGE (aw)-[:ACTIVE_REVISION]->(wr)
        RETURN previous_revisions
        """,
        workspace_id=structure.workspace_id,
        revision_id=structure.revision_id,
    ).single()
    if record is None or not isinstance(record.get("previous_revisions"), list):
        raise IngestionError("Workspace publication did not return its previous revision.")
    previous = record["previous_revisions"]
    if len(previous) > 1:
        raise IngestionError("Workspace has multiple active revisions; refusing publication.")
    return WorkspacePublication(structure.workspace_id, structure.revision_id, previous[0] if previous else None)


def _rollback_workspace_revision(tx, publication: WorkspacePublication) -> None:
    record = tx.run(
        """
        MATCH (aw:ActiveWorkspace {workspace_id: $workspace_id})
        SET aw.publication_version = coalesce(aw.publication_version, 0) + 1
        WITH aw
        MATCH (aw)-[current:ACTIVE_REVISION]->(wr:WorkspaceRevision {revision_id: $revision_id})
        OPTIONAL MATCH (previous:WorkspaceRevision {workspace_id: $workspace_id})
        WHERE previous.revision_id = $previous_revision_id
        WITH aw, current, wr, previous
        WHERE $previous_revision_id IS NULL OR previous IS NOT NULL
        DELETE current
        SET wr.active = false, wr.status = 'staged'
        FOREACH (prior IN CASE WHEN previous IS NULL THEN [] ELSE [previous] END |
            MERGE (aw)-[:ACTIVE_REVISION]->(prior)
            SET prior.active = true, prior.status = 'active'
        )
        RETURN aw.workspace_id AS workspace_id
        """,
        workspace_id=publication.workspace_id,
        revision_id=publication.revision_id,
        previous_revision_id=publication.previous_revision_id,
    ).single()
    if record is None:
        raise IngestionError("Workspace revision changed or its predecessor is unavailable; refusing rollback.")


def rollback_workspace_revision(publication: WorkspacePublication) -> None:
    with GraphDatabase.driver(settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_pass)) as driver:
        with driver.session() as session:
            session.execute_write(_rollback_workspace_revision, publication)


def ingest_to_neo4j(
    structure: ExtractedCodeStructure, progress_callback: ProgressCallback | None = None,
) -> WorkspacePublication:
    def execute_write_or_raise(session, label: str, func, *args):
        try:
            return session.execute_write(func, *args)
        except Exception as exc:
            LOGGER.exception("Neo4j write failed during ingestion", extra={"ingestion_step": label})
            raise IngestionError(f"Neo4j write failed during {label}: {exc}") from exc

    driver = GraphDatabase.driver(settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_pass))
    try:
        with driver.session() as session:
            if progress_callback:
                progress_callback("ingesting", "Persisting parser generation to Neo4j…", 60.0)
            execute_write_or_raise(session, "workspace revision persistence", create_workspace_revision, structure)
            for chunk in _chunked(structure.source_files, 5000):
                execute_write_or_raise(session, "source file persistence", create_source_file_batch, tuple(chunk))
            for chunk in _chunked(structure.classes, 5000):
                execute_write_or_raise(session, "class persistence", create_class_batch, tuple(chunk))
            for chunk in _chunked(structure.methods, 5000):
                execute_write_or_raise(session, "method persistence", create_method_batch, tuple(chunk))
            for chunk in _chunked(structure.fields, 5000):
                execute_write_or_raise(session, "field persistence", create_field_batch, tuple(chunk))
            if structure.nested_relations:
                execute_write_or_raise(session, "nested class relations", link_nested_classes_batch, structure.nested_relations)
            if structure.extends_relations:
                execute_write_or_raise(session, "extends class relations", link_extends_classes_batch, structure.extends_relations)
            if structure.implements_relations:
                execute_write_or_raise(session, "implements class relations", link_implements_classes_batch, structure.implements_relations)
            if structure.calls_relations:
                execute_write_or_raise(session, "resolved call relations", link_calls_batch, structure.calls_relations)
            if structure.call_evidence:
                execute_write_or_raise(session, "call evidence persistence", create_call_evidence_batch, structure.call_evidence)
            if structure.method_field_relations:
                execute_write_or_raise(session, "method-field use relations", link_method_field_use_batch, structure.method_field_relations)
            publication = execute_write_or_raise(
                session, "active revision publication", publish_workspace_revision, structure,
            )
    finally:
        driver.close()
    if progress_callback:
        progress_callback("ingesting", "Neo4j ingestion complete.", 80.0)
    return publication


def ingest(
    java_root_dir: str,
    progress_callback: ProgressCallback | None = None,
    *,
    source_roots: Sequence[str | os.PathLike[str]] | None = None,
) -> WorkspacePublication:
    java_root_dir = os.path.abspath(java_root_dir)
    if not os.path.isdir(java_root_dir):
        if progress_callback:
            progress_callback("error", f"JAVA_ROOT_DIR does not exist: {java_root_dir}", 100.0)
        raise IngestionError(f"JAVA_ROOT_DIR does not exist: {java_root_dir}")
    if progress_callback:
        progress_callback("connecting", "Checking Neo4j availability…", 10.0)
    try:
        driver = GraphDatabase.driver(settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_pass))
        with driver.session() as session:
            session.run("RETURN 1 AS ok").consume()
        driver.close()
    except Exception as exc:
        if progress_callback:
            progress_callback("error", f"Neo4j connection failed: {exc}", 100.0)
        raise IngestionError(f"Neo4j connection failed: {exc}") from exc
    ensure_constraints()
    structure = collect_code_structure(java_root_dir, progress_callback=progress_callback, source_roots=source_roots)
    publication = ingest_to_neo4j(structure, progress_callback=progress_callback)
    if progress_callback:
        progress_callback("ingesting", "Ingestion complete.", 90.0)
    return publication
