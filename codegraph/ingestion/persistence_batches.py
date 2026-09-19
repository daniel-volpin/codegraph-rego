from __future__ import annotations

import json
from typing import Any

from codegraph.ingestion.extraction import (
    GRAPH_SCHEMA_VERSION,
    ExtractedCodeStructure,
)
from codegraph.ingestion.models import ClassEntity, FieldEntity, MethodEntity


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
    serialized = []
    for sf in source_files:
        item = dict(sf)
        diagnostics = item.get("diagnostics") or []
        item["diagnostics"] = [
            json.dumps(d) if isinstance(d, dict) else str(d)
            for d in diagnostics
        ]
        serialized.append(item)
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
        source_files=serialized,
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


def create_config_property_batch(tx, config_properties: tuple[dict[str, Any], ...]) -> None:
    tx.run(
        """
        UNWIND $properties AS item
        MERGE (prop:ConfigProperty {property_key: item.property_key})
        SET prop.config_key = item.config_key,
            prop.value = item.value,
            prop.source_file = item.source_file,
            prop.line = item.line,
            prop.workspace_id = item.workspace_id,
            prop.revision_id = item.revision_id
        """,
        properties=list(config_properties),
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
            call.argument_sources = item.argument_sources,
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
