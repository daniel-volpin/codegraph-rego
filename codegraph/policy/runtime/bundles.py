from __future__ import annotations

import logging
import os
from functools import partial
from pathlib import Path
from typing import Any

from codegraph.common.concurrency import bounded_futures
from codegraph.common.snippet_utils import extract_code_snippet, extract_snippet_by_lines
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
    signature = record.get("signature")
    if not signature:
        return None
    file_path = record.get("file_path")
    if is_test_source_path(file_path):
        return None
    return {
        "signature": signature,
        "name": record.get("name"),
        "class_fqn": record.get("class_fqn"),
        "file_path": file_path,
        "start_line": record.get("start_line"),
        "end_line": record.get("end_line"),
        "modifiers": record.get("modifiers") or [],
        "annotations": _combined_annotations(
            record.get("property_annotations"),
            record.get("annotation_nodes"),
        ),
        "uses_fields": _sorted_used_fields(record.get("uses_fields")),
        "calls": _sorted_non_empty_strings(record.get("calls")),
        "callers": _sorted_non_empty_strings(record.get("callers")),
    }


# Shared context expansion + projection for method snapshots. Both fetchers
# must stay column-identical so _snapshot_from_record sees one record shape.
_METHOD_CONTEXT_AND_RETURN = (
    "OPTIONAL MATCH (cls:Class)-[:DECLARES]->(m) "
    "OPTIONAL MATCH (m)-[:ANNOTATED_WITH]->(ann:Annotation) "
    "OPTIONAL MATCH (m)-[:USES]->(usedField:Field) "
    "OPTIONAL MATCH (m)-[:CALLS]->(callee:Method) "
    "OPTIONAL MATCH (caller:Method)-[:CALLS]->(m) "
    "RETURN coalesce(m.full_signature, m.signature) AS signature, "
    "       m.name AS name, "
    "       m.file_path AS file_path, "
    "       m.start_line AS start_line, "
    "       m.end_line AS end_line, "
    "       m.modifiers AS modifiers, "
    "       m.annotations AS property_annotations, "
    "       cls.fqn AS class_fqn, "
    "       collect(DISTINCT ann.name) AS annotation_nodes, "
    "       collect(DISTINCT CASE WHEN usedField IS NULL "
    "                             THEN NULL "
    "                             ELSE {"
    "                                 name: usedField.name, "
    "                                 type: usedField.type, "
    "                                 class_fqn: usedField.class_fqn"
    "                             } END) AS uses_fields, "
    "       collect(DISTINCT coalesce(callee.full_signature, callee.signature)) AS calls, "
    "       collect(DISTINCT coalesce(caller.full_signature, caller.signature)) AS callers "
)


def fetch_methods_with_context(
    driver,
    *,
    max_bundles: int | None = None,
    workspace_root: str | None = None,
) -> list[dict[str, Any]]:
    cypher = "MATCH (m:Method) "
    params: dict[str, Any] = {}
    if workspace_root:
        cypher += " WHERE m.file_path STARTS WITH $workspace_root "
        params["workspace_root"] = workspace_root
    cypher += _METHOD_CONTEXT_AND_RETURN
    if isinstance(max_bundles, int) and max_bundles > 0:
        cypher += " LIMIT $max_bundles"
        params["max_bundles"] = max_bundles
    snapshots: list[dict[str, Any]] = []
    with driver.session() as session:
        for rec in session.run(cypher, params):
            snapshot = _snapshot_from_record(rec)
            if snapshot is not None:
                snapshots.append(snapshot)
    return snapshots


def fetch_method_snapshot(driver, method_signature: str) -> dict[str, Any] | None:
    cypher = (
        "MATCH (m:Method) "
        "WHERE coalesce(m.full_signature, m.signature) = $method_signature "
        "   OR m.signature = $method_signature "
        "   OR m.full_signature = $method_signature "
        + _METHOD_CONTEXT_AND_RETURN
        + "LIMIT 1"
    )
    with driver.session() as session:
        record = session.run(cypher, method_signature=method_signature).single()
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
        return ""
    source_code = extract_snippet_by_lines(
        source_path.as_posix(),
        method_snapshot.get("start_line"),
        method_snapshot.get("end_line"),
        padding=2,
    )
    if source_code or not method_snapshot.get("name"):
        return source_code
    return extract_code_snippet(source_path.as_posix(), method_snapshot.get("name", ""))


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


def _vector_context(search_service: HybridSearchService | None, method_signature: str) -> list[str]:
    if search_service is None:
        return []
    try:
        return search_service.similar_to_signature(method_signature, top_k=3)
    except Exception as exc:  # pragma: no cover - optional dependency
        LOGGER.debug("Vector lookup failed for %s: %s", method_signature, exc)
        return []


def _taint_paths(taint_path_finder: TaintPathFinder | None, method_signature: str) -> list[dict[str, Any]]:
    if taint_path_finder is None:
        return []
    return taint_path_finder.find_reachable_sinks(method_signature)


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
        if vector_context is None:
            vector_context = _vector_context(search_service, method_snapshot["signature"])
        bundle = build_policy_bundle(
            target_method=method_snapshot["signature"],
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

        taint_paths = _taint_paths(taint_path_finder, method_snapshot["signature"])
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

    method_index = {snapshot["signature"]: snapshot for snapshot in methods if snapshot.get("signature")}
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
