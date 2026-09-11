"""Neo4j graph queries and method snapshot fetching for policy runtime."""

from __future__ import annotations

import logging
from typing import Any

from codegraph.java.service import ADAPTER_VERSION, EXPECTED_BACKEND, JDT_BACKEND_VERSION

LOGGER = logging.getLogger(__name__)


def is_test_source_path(file_path: Any) -> bool:
    """Determine whether a source path points to a unit test file."""
    if not isinstance(file_path, str):
        return False
    normalized = file_path.replace("\\", "/")
    return "/src/test/" in normalized or normalized.startswith("src/test/")


def _sorted_non_empty_strings(values: Any) -> list[str]:
    return sorted(str(value) for value in (values or []) if value)


def _sorted_used_fields(values: Any) -> list[dict[str, Any]]:
    fields = [field for field in (values or []) if field and field.get("name")]
    return sorted(fields, key=lambda field: str(field.get("name") or ""))


def _combined_annotations(property_annotations: Any, annotation_nodes: Any) -> list[str]:
    annotations = list(property_annotations or []) + list(annotation_nodes or [])
    return sorted({annotation for annotation in annotations if annotation})


def _snapshot_from_record(record: Any) -> dict[str, Any] | None:
    method_key = record.get("method_key")
    signature = record.get("signature")
    if not method_key or not signature:
        return None
    file_path = record.get("file_path")
    if is_test_source_path(file_path):
        return None
    return {
        "method_key": method_key,
        "signature": signature,
        "name": record.get("name"),
        "class_fqn": record.get("class_fqn"),
        "declaring_type_key": record.get("declaring_type_key"),
        "file_path": file_path,
        "relative_path": record.get("relative_path"),
        "start_line": record.get("start_line"),
        "end_line": record.get("end_line"),
        "start_byte": record.get("start_byte"),
        "end_byte": record.get("end_byte"),
        "modifiers": record.get("modifiers") or [],
        "annotations": _combined_annotations(
            record.get("property_annotations"),
            record.get("annotation_nodes"),
        ),
        "uses_fields": _sorted_used_fields(record.get("uses_fields")),
        "calls": _sorted_non_empty_strings(record.get("calls")),
        "call_evidence": record.get("call_evidence") or [],
        "callers": _sorted_non_empty_strings(record.get("callers")),
        "workspace_id": record.get("workspace_id"),
        "revision_id": record.get("revision_id"),
        "parser_backend": record.get("parser_backend"),
        "parser_version": record.get("parser_version"),
        "source_sha256": record.get("source_sha256"),
        "range_status": record.get("range_status"),
    }


def _assert_jdt_graph_schema(session) -> None:
    record = session.run(
        """
        CALL () {
            MATCH (m:Method) WHERE m.method_key IS NULL
            RETURN count(m) AS incompatible_methods
        }
        OPTIONAL MATCH (:ActiveWorkspace)-[:ACTIVE_REVISION]->(wr:WorkspaceRevision)
        WITH incompatible_methods, count(CASE WHEN
            wr.schema_version IS NULL OR wr.schema_version <> 'codegraph-jdt/v1'
            OR wr.parser_backend IS NULL OR wr.parser_backend <> $backend
            OR wr.parser_version IS NULL OR wr.parser_version <> $parser_version
            OR wr.adapter_version IS NULL OR wr.adapter_version <> $adapter_version
            THEN wr END) AS incompatible_revisions
        RETURN incompatible_methods + incompatible_revisions AS incompatible_count
        """,
        {"backend": EXPECTED_BACKEND, "parser_version": JDT_BACKEND_VERSION, "adapter_version": ADAPTER_VERSION},
    ).single()
    incompatible_count = int(record.get("incompatible_count") or 0) if record else 0
    if incompatible_count:
        raise RuntimeError(
            "Incompatible graph state detected; explicit rebuild is required before policy/search evaluation."
        )


_ACTIVE_REVISION_MATCH = (
    "MATCH (aw:ActiveWorkspace)-[:ACTIVE_REVISION]->(wr:WorkspaceRevision) "
)
_ACTIVE_REVISION_PREDICATE = (
    "aw.workspace_id = m.workspace_id "
    "  AND wr.workspace_id = m.workspace_id "
    "  AND wr.revision_id = m.revision_id "
    "  AND wr.schema_version = 'codegraph-jdt/v1' "
)

_METHOD_CONTEXT_AND_RETURN = (
    "OPTIONAL MATCH (cls:Class)-[:DECLARES]->(m) "
    "OPTIONAL MATCH (m)-[:ANNOTATED_WITH]->(ann:Annotation) "
    "OPTIONAL MATCH (m)-[:USES]->(usedField:Field) "
    "OPTIONAL MATCH (m)-[:CALLS]->(callee:Method) "
    "OPTIONAL MATCH (m)-[:HAS_CALL]->(call:CallEvidence) "
    "OPTIONAL MATCH (caller:Method)-[:CALLS]->(m) "
    "RETURN m.method_key AS method_key, "
    "       m.signature AS signature, "
    "       m.name AS name, "
    "       m.file_path AS file_path, "
    "       m.relative_path AS relative_path, "
    "       m.start_line AS start_line, "
    "       m.end_line AS end_line, "
    "       m.start_byte AS start_byte, "
    "       m.end_byte AS end_byte, "
    "       m.modifiers AS modifiers, "
    "       m.annotations AS property_annotations, "
    "       m.class_fqn AS class_fqn, "
    "       m.declaring_type_key AS declaring_type_key, "
    "       collect(DISTINCT ann.name) AS annotation_nodes, "
    "       collect(DISTINCT CASE WHEN usedField IS NULL "
    "                             THEN NULL "
    "                             ELSE {"
    "                                 name: usedField.name, "
    "                                 type: usedField.type, "
    "                                 class_fqn: usedField.class_fqn, "
    "                                 field_key: usedField.field_key"
    "                             } END) AS uses_fields, "
    "       collect(DISTINCT callee.method_key) AS calls, "
    "       collect(DISTINCT CASE WHEN call IS NULL THEN NULL ELSE properties(call) END) AS call_evidence, "
    "       collect(DISTINCT caller.method_key) AS callers, "
    "       m.workspace_id AS workspace_id, "
    "       m.revision_id AS revision_id, "
    "       m.parser_backend AS parser_backend, "
    "       m.parser_version AS parser_version, "
    "       m.source_sha256 AS source_sha256, "
    "       m.range_status AS range_status "
)


def validate_graph_generation(driver, *, workspace_root: str | None = None) -> dict[str, Any]:
    """Validate that Neo4j contains only JDT identity graph state."""
    cypher = (
        "MATCH (aw:ActiveWorkspace)-[:ACTIVE_REVISION]->(wr:WorkspaceRevision) "
        "OPTIONAL MATCH (m:Method {workspace_id: wr.workspace_id, revision_id: wr.revision_id}) "
    )
    params: dict[str, Any] = {}
    if workspace_root:
        cypher += "WHERE m.file_path STARTS WITH $workspace_root OR m IS NULL "
        params["workspace_root"] = workspace_root
    cypher += (
        "WITH wr, "
        "     count(DISTINCT m) AS revision_method_count, "
        "     count(DISTINCT CASE "
        "       WHEN m.range_status = 'verified' AND m.start_byte IS NOT NULL AND m.end_byte IS NOT NULL "
        "       THEN m END) AS revision_indexable_method_count "
        "RETURN count(DISTINCT wr) AS workspace_revisions, "
        "       sum(revision_method_count) AS method_count, "
        "       sum(revision_indexable_method_count) AS indexable_method_count, "
        "       collect(DISTINCT wr.schema_version) AS schema_versions, "
        "       collect(DISTINCT wr.parser_backend) AS parser_backends, "
        "       collect({"
        "           workspace_id: wr.workspace_id, "
        "           revision_id: wr.revision_id, "
        "           schema_version: wr.schema_version, "
        "           parser_backend: wr.parser_backend, "
        "           parser_version: wr.parser_version, "
        "           adapter_version: wr.adapter_version, "
        "           method_count: revision_method_count, "
        "           indexable_method_count: revision_indexable_method_count"
        "       }) AS active_revisions"
    )
    with driver.session() as session:
        _assert_jdt_graph_schema(session)
        record = session.run(cypher, params).single()
    return {
        "workspace_revisions": int(record.get("workspace_revisions") or 0) if record else 0,
        "method_count": int(record.get("method_count") or 0) if record else 0,
        "indexable_method_count": int(record.get("indexable_method_count") or 0) if record else 0,
        "schema_versions": _sorted_non_empty_strings(record.get("schema_versions") if record else []),
        "parser_backends": _sorted_non_empty_strings(record.get("parser_backends") if record else []),
        "active_revisions": sorted(
            (
                {
                    "workspace_id": str(item.get("workspace_id") or ""),
                    "revision_id": str(item.get("revision_id") or ""),
                    "schema_version": str(item.get("schema_version") or ""),
                    "parser_backend": str(item.get("parser_backend") or ""),
                    "parser_version": str(item.get("parser_version") or ""),
                    "adapter_version": str(item.get("adapter_version") or ""),
                    "method_count": int(item.get("method_count") or 0),
                    "indexable_method_count": int(item.get("indexable_method_count") or 0),
                }
                for item in (record.get("active_revisions") if record else []) or []
                if isinstance(item, dict)
            ),
            key=lambda item: (item["workspace_id"], item["revision_id"]),
        ),
    }


def fetch_methods_with_context(
    driver,
    *,
    max_bundles: int | None = None,
    workspace_root: str | None = None,
) -> list[dict[str, Any]]:
    """Fetch method snapshots and their connected graph context from Neo4j."""
    cypher = "MATCH (m:Method) " + _ACTIVE_REVISION_MATCH + "WHERE " + _ACTIVE_REVISION_PREDICATE
    params: dict[str, Any] = {}
    if workspace_root:
        cypher += " AND m.file_path STARTS WITH $workspace_root "
        params["workspace_root"] = workspace_root
    cypher += _METHOD_CONTEXT_AND_RETURN
    if isinstance(max_bundles, int) and max_bundles > 0:
        cypher += " LIMIT $max_bundles"
        params["max_bundles"] = max_bundles
    snapshots: list[dict[str, Any]] = []
    with driver.session() as session:
        _assert_jdt_graph_schema(session)
        for rec in session.run(cypher, params):
            snapshot = _snapshot_from_record(rec)
            if snapshot is not None:
                snapshots.append(snapshot)
    return snapshots


def fetch_method_snapshot(driver, method_key: str) -> dict[str, Any] | None:
    """Fetch a single method snapshot by its unique namespaced method_key."""
    cypher = (
        "MATCH (m:Method) "
        + _ACTIVE_REVISION_MATCH
        + "WHERE m.method_key = $method_key AND "
        + _ACTIVE_REVISION_PREDICATE
        + _METHOD_CONTEXT_AND_RETURN
        + "LIMIT 1"
    )
    with driver.session() as session:
        _assert_jdt_graph_schema(session)
        record = session.run(cypher, method_key=method_key).single()
        return _snapshot_from_record(record) if record else None
