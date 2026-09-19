"""Policy evidence bundle generation, method source extraction, and policy input envelope serialization."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from functools import partial
from pathlib import Path
from typing import Any

from codegraph.common.concurrency import bounded_futures
from codegraph.config import settings
from codegraph.db import shared_neo4j_driver
from codegraph.ingestion.config_facts import (
    ConfigProperty,
    ResolvedProperty,
    resolve_properties,
)
from codegraph.policy.runtime.bundles_helpers import (
    _build_helper_summaries,
    _config_context,
    _extract_method_source,
    _graph_context,
    _record_evidence_span_attributes,
    _resolve_bundle_source_path,
    _source_views,
    _tracer,
    _vector_context,
    load_hybrid_search,
    resolve_source_path,
)
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
    fetch_config_properties,
    fetch_method_snapshot,
    fetch_methods_with_context,
    is_test_source_path,
    validate_graph_generation,
)
from codegraph.policy.source_analysis import analyze_policy_indicators
from codegraph.search.service import HybridSearchService

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
    "resolve_workspace_config",
    "validate_graph_generation",
]

LOGGER = logging.getLogger(__name__)


def build_evidence_bundle_from_source(
    method_snapshot: dict[str, Any],
    source_code: str,
    *,
    search_service: HybridSearchService | None = None,
    method_index: dict[str, dict[str, Any]] | None = None,
    bundle_file_path: str | None = None,
    vector_context: list[str] | None = None,
    resolved_config: Mapping[str, ResolvedProperty] | None = None,
) -> dict[str, Any]:
    with _tracer.start_as_current_span("evidence.build") as span:
        span.set_attribute("method_key", str(method_snapshot.get("method_key") or ""))
        span.set_attribute("method_signature", str(method_snapshot.get("signature") or ""))
        span.set_attribute("file_path", str(method_snapshot.get("file_path") or ""))

        source_code_active, source_code_substring_safe = _source_views(source_code)

        graph_context = _graph_context(method_snapshot)
        config_context = _config_context(method_snapshot, resolved_config)
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
            source_code_raw=source_code,
            graph_context=graph_context,
            config_context=config_context,
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
    resolved_config: Mapping[str, ResolvedProperty] | None = None,
) -> dict[str, Any]:
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
        resolved_config=resolved_config,
    )


def resolve_workspace_config() -> dict[str, ResolvedProperty]:
    try:
        records = fetch_config_properties(shared_neo4j_driver())
    except Exception as exc:
        LOGGER.warning("Configuration facts unavailable; config-backed rules stay silent: %s", exc)
        return {}
    declarations = [
        ConfigProperty(
            key=record["config_key"],
            value=record.get("value") or "",
            source_file=record.get("source_file") or "",
            line=int(record.get("line") or 0),
        )
        for record in records
    ]
    resolved = resolve_properties(declarations)
    ambiguous = sorted(key for key, entry in resolved.items() if entry.is_ambiguous)
    if ambiguous:
        LOGGER.warning("Configuration keys declared with conflicting values: %s", ", ".join(ambiguous))
    LOGGER.info("Resolved %d configuration keys for the active revision", len(resolved))
    return resolved


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
    resolved_config = resolve_workspace_config()

    method_index = {snapshot["method_key"]: snapshot for snapshot in methods if snapshot.get("method_key")}
    bundles: list[dict[str, Any]] = [None] * len(methods)
    build = partial(
        build_evidence_bundle,
        search_service=hybrid_search,
        method_index=method_index,
        resolved_config=resolved_config,
    )
    for index, future in bounded_futures(build, methods, max_workers=settings.policy_workers):
        bundles[index] = future.result()

    return serialize_policy_input_envelope(
        bundles=bundles,
        rules_catalog=load_iso_rules(),
        catalog=get_policy_catalog_entries(),
    )
