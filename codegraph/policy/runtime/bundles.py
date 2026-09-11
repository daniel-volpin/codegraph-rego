from __future__ import annotations

import hashlib
import logging
import os
from functools import partial
from pathlib import Path
from typing import Any

from codegraph.common.concurrency import bounded_futures
from codegraph.config import settings
from codegraph.db import shared_neo4j_driver
from codegraph.policy.helper_summaries import DirectCallSummaryBuilder
from codegraph.policy.source_analysis import analyze_policy_indicators
from codegraph.policy.source_analysis_core import strip_java_lexical_noise
from codegraph.policy.taint_graph import TaintPathFinder
from codegraph.search.service import HybridSearchService
from codegraph.telemetry import get_tracer

from .catalog import get_policy_catalog_entries, load_iso_rules
from .contracts import build_policy_bundle, serialize_policy_bundle, serialize_policy_input_envelope

_tracer = get_tracer("codegraph.policy.bundles")

LOGGER = logging.getLogger(__name__)

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_THIS_DIR, os.pardir, os.pardir, os.pardir))
_HYBRID_SEARCH: HybridSearchService | None = None
_HELPER_SUMMARY_BUILDER = DirectCallSummaryBuilder()


def load_hybrid_search() -> HybridSearchService | None:
    global _HYBRID_SEARCH
    if _HYBRID_SEARCH is not None:
        return _HYBRID_SEARCH
    try:
        _HYBRID_SEARCH = HybridSearchService()
    except Exception as exc:  # pragma: no cover - optional dependency
        LOGGER.warning("Hybrid search unavailable for evidence bundles: %s", exc)
        _HYBRID_SEARCH = None
    return _HYBRID_SEARCH


def is_test_source_path(file_path: Any) -> bool:
    if not isinstance(file_path, str):
        return False
    normalized = file_path.replace("\\", "/")
    return "/src/test/" in normalized


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
    from codegraph.java.service import ADAPTER_VERSION, EXPECTED_BACKEND, JDT_BACKEND_VERSION

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


def validate_graph_generation(driver, *, workspace_root: str | None = None) -> dict[str, Any]:
    """Validate that Neo4j contains only JDT identity graph state.

    Readiness/startup callers should use this before policy or search preload.
    It refuses old Method nodes without ``method_key`` and returns non-secret
    generation metadata that can be reported in health details.
    """
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


# Shared context expansion + projection for method snapshots. Both fetchers
# must stay column-identical so _snapshot_from_record sees one record shape.
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


def fetch_methods_with_context(
    driver,
    *,
    max_bundles: int | None = None,
    workspace_root: str | None = None,
) -> list[dict[str, Any]]:
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


def resolve_source_path(file_path: str | None) -> Path | None:
    if not file_path:
        return None
    path = Path(file_path)
    if path.is_file():
        return path
    candidate = Path(_PROJECT_ROOT) / path
    if candidate.is_file():
        return candidate
    return None


def _source_override_path(source_path_override: str | Path | None) -> str | None:
    if isinstance(source_path_override, Path):
        return source_path_override.as_posix()
    return source_path_override


def _resolve_bundle_source_path(
    resolved_path: Path | None,
    source_path_override: str | Path | None,
) -> Path | None:
    override = _source_override_path(source_path_override)
    return resolve_source_path(override) if override else resolved_path


def _extract_method_source(method_snapshot: dict[str, Any], source_path: Path | None) -> str:
    if source_path is None:
        raise ValueError("policy_source_unavailable")
    raw = source_path.read_bytes()
    expected_hash = method_snapshot.get("source_sha256")
    if not expected_hash or hashlib.sha256(raw).hexdigest() != expected_hash:
        raise ValueError("policy_source_hash_mismatch")
    start_byte = method_snapshot.get("start_byte")
    end_byte = method_snapshot.get("end_byte")
    range_status = method_snapshot.get("range_status")
    if range_status == "absent" and start_byte is None and end_byte is None:
        return ""
    if (
        range_status != "verified"
        or type(start_byte) is not int
        or type(end_byte) is not int
        or not 0 <= start_byte < end_byte <= len(raw)
    ):
        raise ValueError("policy_source_range_invalid")
    return raw[start_byte:end_byte].decode("utf-8")


def _source_views(source_code: str) -> tuple[str, str]:
    if not source_code:
        return source_code, source_code
    active = strip_java_lexical_noise(source_code, strip_string_literals=False)
    substring_safe = strip_java_lexical_noise(source_code, strip_string_literals=True)
    return active, substring_safe


def _graph_context(method_snapshot: dict[str, Any]) -> dict[str, Any]:
    return {
        "annotations": method_snapshot.get("annotations") or [],
        "uses_fields": method_snapshot.get("uses_fields") or [],
        "calls": method_snapshot.get("calls") or [],
        "callers": method_snapshot.get("callers") or [],
    }


def _build_helper_summaries(
    *,
    source_code_active: str,
    method_snapshot: dict[str, Any],
    method_index: dict[str, dict[str, Any]] | None,
) -> dict[str, Any]:
    if method_index is None:
        return {}
    return _HELPER_SUMMARY_BUILDER.build(
        current_source=source_code_active,
        method_snapshot=method_snapshot,
        method_index=method_index,
    )


def _vector_context(search_service: HybridSearchService | None, method_key: str) -> list[str]:
    if search_service is None:
        return []
    try:
        return search_service.similar_to_method_key(method_key, top_k=3)
    except Exception as exc:  # pragma: no cover - optional dependency
        LOGGER.debug("Vector lookup failed for %s: %s", method_key, exc)
        return []


def _taint_paths(taint_path_finder: TaintPathFinder | None, method_key: str) -> list[dict[str, Any]]:
    if taint_path_finder is None:
        return []
    return taint_path_finder.find_reachable_sinks(method_key)


def _record_evidence_span_attributes(
    span: Any,
    *,
    source_code: str,
    graph_context: dict[str, Any],
    vector_context: list[str],
    helper_summaries: dict[str, Any],
    taint_paths: list[dict[str, Any]],
    analysis_flags: dict[str, Any],
) -> None:
    span.set_attribute("source_code_lines", len(source_code.splitlines()) if source_code else 0)
    span.set_attribute("source_code_available", bool(source_code))
    graph_node_count = sum(
        len(graph_context.get(key) or [])
        for key in ("annotations", "uses_fields", "calls", "callers")
    )
    span.set_attribute("graph_nodes_count", graph_node_count)
    span.set_attribute("vector_results_count", len(vector_context))
    span.set_attribute("helper_summaries_count", len(helper_summaries))
    span.set_attribute("taint_paths_count", len(taint_paths))
    max_taint_hops = max((path.get("hops", 0) for path in taint_paths), default=0)
    span.set_attribute("taint_hops_max", max_taint_hops)
    analysis_flag_count = sum(1 for value in analysis_flags.values() if value)
    span.set_attribute("analysis_flags_active", analysis_flag_count)


def build_evidence_bundle_from_source(
    method_snapshot: dict[str, Any],
    source_code: str,
    *,
    search_service: HybridSearchService | None = None,
    method_index: dict[str, dict[str, Any]] | None = None,
    taint_path_finder: TaintPathFinder | None = None,
    bundle_file_path: str | None = None,
    vector_context: list[str] | None = None,
) -> dict[str, Any]:
    """Canonical source-text -> policy-input construction.

    This is the single owner of the evidence semantics Rego evaluates
    against: lexical source views, analysis flags, helper summaries, and
    taint-path shape. Every evaluation path — on-disk methods and virtual
    remediation candidates alike — must go through here so the policy
    input cannot fork. Pure with respect to the workspace and graph; the
    only optional I/O is the vector lookup when ``vector_context`` is not
    supplied.
    """
    with _tracer.start_as_current_span("evidence.build") as span:
        span.set_attribute("method_key", str(method_snapshot.get("method_key") or ""))
        span.set_attribute("method_signature", str(method_snapshot.get("signature") or ""))
        span.set_attribute("file_path", str(method_snapshot.get("file_path") or ""))

        source_code_active, source_code_substring_safe = _source_views(source_code)

        graph_context = _graph_context(method_snapshot)
        analysis_flags = analyze_policy_indicators(source_code_active)
        helper_summaries = _build_helper_summaries(
            source_code_active=source_code_active,
            method_snapshot=method_snapshot,
            method_index=method_index,
        )
        method_key = method_snapshot.get("method_key")
        if vector_context is None:
            vector_context = _vector_context(search_service, method_key) if method_key else []
        bundle = build_policy_bundle(
            target_method=method_snapshot["signature"],
            method_key=method_key,
            method_name=method_snapshot.get("name"),
            class_fqn=method_snapshot.get("class_fqn"),
            file_path=bundle_file_path if bundle_file_path is not None else method_snapshot.get("file_path"),
            start_line=method_snapshot.get("start_line"),
            end_line=method_snapshot.get("end_line"),
            modifiers=method_snapshot.get("modifiers") or [],
            source_code=source_code_substring_safe,
            # Preserve the original source for downstream consumers that
            # need human-readable text (LLM citation grounding,
            # evidence-card rendering, audit excerpts). Rego policies see
            # ``source_code`` (the substring-safe view) and never read this
            # field; the Python regex layer ran on source_code_active above
            # to set the analysis flags.
            source_code_raw=source_code,
            graph_context=graph_context,
            vector_context=vector_context,
            analysis_flags=analysis_flags,
            helper_summaries=helper_summaries,
        )
        result = serialize_policy_bundle(bundle)
        result["workspace_id"] = method_snapshot.get("workspace_id")
        result["revision_id"] = method_snapshot.get("revision_id")
        result["parser"] = {
            "backend": method_snapshot.get("parser_backend"),
            "version": method_snapshot.get("parser_version"),
            "range_status": method_snapshot.get("range_status"),
            "source_sha256": method_snapshot.get("source_sha256"),
        }

        taint_paths = _taint_paths(taint_path_finder, method_key) if method_key else []
        result["taint_paths"] = taint_paths

        _record_evidence_span_attributes(
            span,
            source_code=source_code,
            graph_context=graph_context,
            vector_context=vector_context,
            helper_summaries=helper_summaries,
            taint_paths=taint_paths,
            analysis_flags=analysis_flags,
        )

        return result


def build_evidence_bundle(
    method_snapshot: dict[str, Any],
    search_service: HybridSearchService | None = None,
    method_index: dict[str, dict[str, Any]] | None = None,
    source_path_override: str | Path | None = None,
    taint_path_finder: TaintPathFinder | None = None,
) -> dict[str, Any]:
    """On-disk variant: extract the method source, then delegate to the core."""
    file_path = method_snapshot.get("file_path")
    resolved_path = resolve_source_path(file_path)
    source_path = _resolve_bundle_source_path(resolved_path, source_path_override)
    source_code = _extract_method_source(method_snapshot, source_path)
    return build_evidence_bundle_from_source(
        method_snapshot,
        source_code,
        search_service=search_service,
        method_index=method_index,
        taint_path_finder=taint_path_finder,
        bundle_file_path=resolved_path.as_posix() if resolved_path else file_path,
    )


def build_policy_input(
    *,
    max_bundles: int | None = None,
    workspace_root: str | None = None,
) -> dict[str, Any]:
    methods = fetch_methods_with_context(
        shared_neo4j_driver(),
        max_bundles=max_bundles,
        workspace_root=workspace_root,
    )
    hybrid_search = load_hybrid_search()

    method_index = {snapshot["method_key"]: snapshot for snapshot in methods if snapshot.get("method_key")}
    taint_finder = TaintPathFinder(method_index)
    bundles: list[dict[str, Any]] = [None] * len(methods)  # type: ignore[list-item]
    build = partial(
        build_evidence_bundle, search_service=hybrid_search, method_index=method_index, taint_path_finder=taint_finder,
    )
    for index, future in bounded_futures(build, methods, max_workers=settings.policy_workers):
        bundles[index] = future.result()

    return serialize_policy_input_envelope(
        bundles=bundles,
        rules_catalog=load_iso_rules(),
        catalog=get_policy_catalog_entries(),
    )
