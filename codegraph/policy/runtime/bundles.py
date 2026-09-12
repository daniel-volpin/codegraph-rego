"""Policy evidence bundle generation, method source extraction, and policy input envelope serialization."""

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
from codegraph.policy.runtime.catalog import get_policy_catalog_entries, load_iso_rules
from codegraph.policy.runtime.contracts import (
    build_policy_bundle,
    serialize_policy_bundle,
    serialize_policy_input_envelope,
)
from codegraph.policy.runtime.graph_queries import (
    _assert_jdt_graph_schema,
    _combined_annotations,
    _snapshot_from_record,
    _sorted_non_empty_strings,
    _sorted_used_fields,
    fetch_method_snapshot,
    fetch_methods_with_context,
    is_test_source_path,
    validate_graph_generation,
)
from codegraph.policy.source_analysis import analyze_policy_indicators
from codegraph.policy.source_analysis_core import strip_java_lexical_noise
from codegraph.search.service import HybridSearchService
from codegraph.telemetry import get_tracer

__all__ = [
    "_assert_jdt_graph_schema",
    "_combined_annotations",
    "_snapshot_from_record",
    "_sorted_non_empty_strings",
    "_sorted_used_fields",
    "build_evidence_bundle",
    "build_evidence_bundle_from_source",
    "build_policy_input",
    "fetch_method_snapshot",
    "fetch_methods_with_context",
    "is_test_source_path",
    "load_hybrid_search",
    "resolve_source_path",
    "validate_graph_generation",
]

_tracer = get_tracer("codegraph.policy.bundles")
LOGGER = logging.getLogger(__name__)

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_THIS_DIR, os.pardir, os.pardir, os.pardir))
_HYBRID_SEARCH: HybridSearchService | None = None
_HELPER_SUMMARY_BUILDER = DirectCallSummaryBuilder()


def load_hybrid_search() -> HybridSearchService | None:
    """Load or reuse the singleton hybrid search service."""
    global _HYBRID_SEARCH
    if _HYBRID_SEARCH is not None:
        return _HYBRID_SEARCH
    try:
        _HYBRID_SEARCH = HybridSearchService()
    except Exception as exc:  # pragma: no cover - optional dependency
        LOGGER.warning("Hybrid search unavailable for evidence bundles: %s", exc)
        _HYBRID_SEARCH = None
    return _HYBRID_SEARCH


def resolve_source_path(file_path: str | None) -> Path | None:
    """Resolve a source file path against the filesystem or workspace project root."""
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


def _record_evidence_span_attributes(
    span: Any,
    *,
    source_code: str,
    graph_context: dict[str, Any],
    vector_context: list[str],
    helper_summaries: dict[str, Any],
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
    analysis_flag_count = sum(1 for value in analysis_flags.values() if value)
    span.set_attribute("analysis_flags_active", analysis_flag_count)


def build_evidence_bundle_from_source(
    method_snapshot: dict[str, Any],
    source_code: str,
    *,
    search_service: HybridSearchService | None = None,
    method_index: dict[str, dict[str, Any]] | None = None,
    bundle_file_path: str | None = None,
    vector_context: list[str] | None = None,
) -> dict[str, Any]:
    """Canonical source-text -> policy-input construction.

    This is the single owner of the evidence semantics Rego evaluates
    against: lexical source views, analysis flags, and helper summaries.
    Every evaluation path — on-disk methods and virtual
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

        _record_evidence_span_attributes(
            span,
            source_code=source_code,
            graph_context=graph_context,
            vector_context=vector_context,
            helper_summaries=helper_summaries,
            analysis_flags=analysis_flags,
        )

        return result


def build_evidence_bundle(
    method_snapshot: dict[str, Any],
    search_service: HybridSearchService | None = None,
    method_index: dict[str, dict[str, Any]] | None = None,
    source_path_override: str | Path | None = None,
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
    bundles: list[dict[str, Any]] = [None] * len(methods)  # type: ignore[list-item]
    build = partial(build_evidence_bundle, search_service=hybrid_search, method_index=method_index)
    for index, future in bounded_futures(build, methods, max_workers=settings.policy_workers):
        bundles[index] = future.result()

    return serialize_policy_input_envelope(
        bundles=bundles,
        rules_catalog=load_iso_rules(),
        catalog=get_policy_catalog_entries(),
    )
