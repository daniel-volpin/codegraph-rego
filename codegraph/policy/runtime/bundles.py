from __future__ import annotations

import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional

from codegraph.common.snippet_utils import extract_code_snippet, extract_snippet_by_lines
from codegraph.db import get_neo4j_driver
from codegraph.policy.helper_summaries import DirectCallSummaryBuilder
from codegraph.policy.source_analysis import analyze_policy_indicators
from codegraph.policy.source_analysis_core import strip_java_lexical_noise
from codegraph.search.service import HybridSearchService
from codegraph.policy.taint_graph import TaintPathFinder
from codegraph.telemetry import get_tracer
from .catalog import get_policy_catalog_entries, load_iso_rules
from .contracts import build_policy_bundle, serialize_policy_bundle, serialize_policy_input_envelope

_tracer = get_tracer("codegraph.policy.bundles")

LOGGER = logging.getLogger(__name__)

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_THIS_DIR, os.pardir, os.pardir, os.pardir))
_HYBRID_SEARCH: Optional[HybridSearchService] = None
_HELPER_SUMMARY_BUILDER = DirectCallSummaryBuilder()


def load_hybrid_search() -> Optional[HybridSearchService]:
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


def fetch_methods_with_context(
    driver,
    *,
    max_bundles: int | None = None,
    workspace_root: str | None = None,
) -> List[Dict[str, Any]]:
    cypher = "MATCH (m:Method) "
    params: Dict[str, Any] = {}
    if workspace_root:
        cypher += " WHERE m.file_path STARTS WITH $workspace_root "
        params["workspace_root"] = workspace_root
    cypher += (
        "OPTIONAL MATCH (cls:Class)-[:DECLARES]->(m) "
        "OPTIONAL MATCH (m)-[:ANNOTATED_WITH]->(ann:Annotation) "
        "OPTIONAL MATCH (m)-[:USES]->(usedField:Field) "
        "OPTIONAL MATCH (m)-[:CALLS]->(callee:Method) "
        "OPTIONAL MATCH (caller:Method)-[:CALLS]->(m) "
    )
    cypher += (
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
    if isinstance(max_bundles, int) and max_bundles > 0:
        cypher += " LIMIT $max_bundles"
        params["max_bundles"] = max_bundles
    snapshots: List[Dict[str, Any]] = []
    with driver.session() as session:
        for rec in session.run(cypher, params):
            signature = rec.get("signature")
            if not signature:
                continue
            file_path = rec.get("file_path")
            if is_test_source_path(file_path):
                continue
            uses_fields = [field for field in (rec.get("uses_fields") or []) if field and field.get("name")]
            annotations = rec.get("property_annotations") or []
            annotation_nodes = rec.get("annotation_nodes") or []
            combined_annotations = sorted({a for a in annotations + annotation_nodes if a})
            snapshots.append(
                {
                    "signature": signature,
                    "name": rec.get("name"),
                    "class_fqn": rec.get("class_fqn"),
                    "file_path": file_path,
                    "start_line": rec.get("start_line"),
                    "end_line": rec.get("end_line"),
                    "modifiers": rec.get("modifiers") or [],
                    "annotations": combined_annotations,
                    "uses_fields": uses_fields,
                    "calls": rec.get("calls") or [],
                    "callers": rec.get("callers") or [],
                }
            )
    return snapshots


def fetch_method_snapshot(driver, method_signature: str) -> Dict[str, Any] | None:
    cypher = (
        "MATCH (m:Method) "
        "WHERE coalesce(m.full_signature, m.signature) = $method_signature "
        "   OR m.signature = $method_signature "
        "   OR m.full_signature = $method_signature "
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
        "LIMIT 1"
    )
    with driver.session() as session:
        record = session.run(cypher, method_signature=method_signature).single()
        if not record:
            return None
        uses_fields = [field for field in (record.get("uses_fields") or []) if field and field.get("name")]
        annotations = record.get("property_annotations") or []
        annotation_nodes = record.get("annotation_nodes") or []
        combined_annotations = sorted({a for a in annotations + annotation_nodes if a})
        return {
            "signature": record.get("signature"),
            "name": record.get("name"),
            "class_fqn": record.get("class_fqn"),
            "file_path": record.get("file_path"),
            "start_line": record.get("start_line"),
            "end_line": record.get("end_line"),
            "modifiers": record.get("modifiers") or [],
            "annotations": combined_annotations,
            "uses_fields": uses_fields,
            "calls": record.get("calls") or [],
            "callers": record.get("callers") or [],
        }


def resolve_source_path(file_path: Optional[str]) -> Optional[Path]:
    if not file_path:
        return None
    path = Path(file_path)
    if path.is_file():
        return path
    candidate = Path(_PROJECT_ROOT) / path
    if candidate.is_file():
        return candidate
    return None


def build_evidence_bundle(
    method_snapshot: Dict[str, Any],
    search_service: Optional[HybridSearchService] = None,
    method_index: Optional[Dict[str, Dict[str, Any]]] = None,
    source_path_override: str | Path | None = None,
    taint_path_finder: Optional[TaintPathFinder] = None,
) -> Dict[str, Any]:
    with _tracer.start_as_current_span("evidence.build") as span:
        span.set_attribute("method_signature", str(method_snapshot.get("signature") or ""))
        span.set_attribute("file_path", str(method_snapshot.get("file_path") or ""))

        file_path = method_snapshot.get("file_path")
        resolved_path = resolve_source_path(file_path)
        if isinstance(source_path_override, Path):
            source_path_override = source_path_override.as_posix()
        source_path = resolve_source_path(source_path_override) if source_path_override else resolved_path
        source_code = ""
        if source_path is not None:
            source_code = extract_snippet_by_lines(
                source_path.as_posix(),
                method_snapshot.get("start_line"),
                method_snapshot.get("end_line"),
                padding=2,
            )
            if not source_code and method_snapshot.get("name"):
                source_code = extract_code_snippet(source_path.as_posix(), method_snapshot.get("name", ""))

        # Two lexically-cleaned views of the source, plus the raw
        # original:
        #   * source_code_active: comments stripped, string and char
        #     literal contents PRESERVED. The Python regex layer in
        #     codegraph.policy.analysis matches structurally-anchored
        #     patterns that intentionally inspect literal contents
        #     (for example, MessageDigest.getInstance("MD5")), so it
        #     needs literals retained.
        #   * source_code_substring_safe: comments AND literal contents
        #     stripped. The OPA/Rego rules perform naive contains(...)
        #     matching on input.source_code; this view eliminates the
        #     entire lexical-FP class for substring rules.
        #   * source_code (raw) is preserved on the bundle as
        #     source_code_raw for downstream consumers that need
        #     human-readable text (LLM citation grounding,
        #     evidence-card rendering, audit excerpts).
        if source_code:
            source_code_active = strip_java_lexical_noise(source_code, strip_string_literals=False)
            source_code_substring_safe = strip_java_lexical_noise(source_code, strip_string_literals=True)
        else:
            source_code_active = source_code
            source_code_substring_safe = source_code

        graph_context = {
            "annotations": method_snapshot.get("annotations") or [],
            "uses_fields": method_snapshot.get("uses_fields") or [],
            "calls": method_snapshot.get("calls") or [],
            "callers": method_snapshot.get("callers") or [],
        }
        analysis_flags = analyze_policy_indicators(source_code_active)
        helper_summaries = (
            _HELPER_SUMMARY_BUILDER.build(
                current_source=source_code_active,
                method_snapshot=method_snapshot,
                method_index=method_index or {},
            )
            if method_index is not None
            else {}
        )
        vector_context: List[str] = []
        if search_service is not None:
            try:
                vector_context = search_service.similar_to_signature(method_snapshot["signature"], top_k=3)
            except Exception as exc:  # pragma: no cover - optional dependency
                LOGGER.debug("Vector lookup failed for %s: %s", method_snapshot["signature"], exc)
        bundle = build_policy_bundle(
            target_method=method_snapshot["signature"],
            method_name=method_snapshot.get("name"),
            class_fqn=method_snapshot.get("class_fqn"),
            file_path=resolved_path.as_posix() if resolved_path else file_path,
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

        taint_paths = (
            taint_path_finder.find_reachable_sinks(method_snapshot["signature"])
            if taint_path_finder is not None
            else []
        )
        result["taint_paths"] = taint_paths

        # Span attributes summarising evidence quality
        span.set_attribute("source_code_lines", len(source_code.splitlines()) if source_code else 0)
        span.set_attribute("source_code_available", bool(source_code))
        graph_node_count = (
            len(graph_context.get("annotations") or [])
            + len(graph_context.get("uses_fields") or [])
            + len(graph_context.get("calls") or [])
            + len(graph_context.get("callers") or [])
        )
        span.set_attribute("graph_nodes_count", graph_node_count)
        span.set_attribute("vector_results_count", len(vector_context))
        span.set_attribute("helper_summaries_count", len(helper_summaries))
        span.set_attribute("taint_paths_count", len(taint_paths))
        max_taint_hops = max((p.get("hops", 0) for p in taint_paths), default=0)
        span.set_attribute("taint_hops_max", max_taint_hops)
        analysis_flag_count = sum(1 for v in analysis_flags.values() if v)
        span.set_attribute("analysis_flags_active", analysis_flag_count)

        return result


def build_policy_input(
    *,
    max_bundles: int | None = None,
    workspace_root: str | None = None,
) -> Dict[str, Any]:
    driver = get_neo4j_driver()
    try:
        methods = fetch_methods_with_context(
            driver,
            max_bundles=max_bundles,
            workspace_root=workspace_root,
        )
    finally:
        driver.close()
    hybrid_search = load_hybrid_search()

    workers = min(32, (os.cpu_count() or 4) + 4)
    method_index = {snapshot["signature"]: snapshot for snapshot in methods if snapshot.get("signature")}
    taint_finder = TaintPathFinder(method_index)
    bundles: List[Dict[str, Any]] = [None] * len(methods)  # type: ignore[list-item]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        future_to_idx = {
            pool.submit(build_evidence_bundle, method, hybrid_search, method_index, None, taint_finder): idx
            for idx, method in enumerate(methods)
        }
        for future in as_completed(future_to_idx):
            bundles[future_to_idx[future]] = future.result()

    return serialize_policy_input_envelope(
        bundles=bundles,
        rules_catalog=load_iso_rules(),
        catalog=get_policy_catalog_entries(),
    )
