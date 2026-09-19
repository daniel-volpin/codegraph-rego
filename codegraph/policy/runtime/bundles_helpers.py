from __future__ import annotations

import hashlib
import logging
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from codegraph.ingestion.config_facts import ResolvedProperty
from codegraph.policy.helper_summaries import DirectCallSummaryBuilder
from codegraph.policy.source_analysis_core import strip_java_lexical_noise
from codegraph.search.service import HybridSearchService
from codegraph.telemetry import get_tracer

_tracer = get_tracer("codegraph.policy.bundles")
LOGGER = logging.getLogger(__name__)

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_THIS_DIR, os.pardir, os.pardir, os.pardir))
_HYBRID_SEARCH: HybridSearchService | None = None
_HELPER_SUMMARY_BUILDER = DirectCallSummaryBuilder()

_CONFIG_ACCESSOR_NAMES = frozenset({"getProperty", "getString"})


def load_hybrid_search() -> HybridSearchService | None:
    global _HYBRID_SEARCH
    if _HYBRID_SEARCH is not None:
        return _HYBRID_SEARCH
    try:
        _HYBRID_SEARCH = HybridSearchService()
    except Exception as exc:
        LOGGER.warning("Hybrid search unavailable for evidence bundles: %s", exc)
        _HYBRID_SEARCH = None
    return _HYBRID_SEARCH


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


def _string_literal(argument_source: str | None) -> str | None:
    if not argument_source:
        return None
    text = argument_source.strip()
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        return text[1:-1]
    return None


def _config_context(
    method_snapshot: dict[str, Any],
    resolved_config: Mapping[str, ResolvedProperty] | None,
) -> dict[str, Any]:
    if not resolved_config:
        return {"resolved": []}

    entries: dict[str, dict[str, Any]] = {}
    for call in method_snapshot.get("call_evidence") or []:
        if not isinstance(call, dict) or call.get("name") not in _CONFIG_ACCESSOR_NAMES:
            continue
        arguments = call.get("argument_sources") or []
        key = _string_literal(arguments[0]) if arguments else None
        if key is None or key in entries:
            continue
        resolution = resolved_config.get(key)
        if resolution is None:
            continue
        declaration = resolution.sources[0]
        entries[key] = {
            "key": key,
            "value": resolution.value,
            "source_file": declaration.source_file,
            "line": declaration.line,
            "ambiguous": resolution.is_ambiguous,
            "conflicting_values": list(resolution.conflicting_values),
        }
    return {"resolved": [entries[key] for key in sorted(entries)]}


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
    except Exception as exc:
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
