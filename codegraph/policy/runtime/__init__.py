"""Internal policy evaluation runtime and bundle construction."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from codegraph.policy.runtime.bundles import (
        build_evidence_bundle,
        build_evidence_bundle_from_source,
        build_policy_input,
        fetch_method_snapshot,
        fetch_methods_with_context,
        resolve_source_path,
        validate_graph_generation,
    )
    from codegraph.policy.runtime.catalog import (
        get_policy_catalog_entries,
        load_iso_rules,
    )
    from codegraph.policy.runtime.contracts import (
        build_policy_bundle,
        normalize_policy_bundle_mapping,
        serialize_policy_bundle,
        serialize_policy_input_envelope,
    )
    from codegraph.policy.runtime.graph_queries import (
        is_test_source_path,
    )
    from codegraph.policy.runtime.opa import (
        normalize_violation_payload,
    )

__all__ = [
    "build_evidence_bundle",
    "build_evidence_bundle_from_source",
    "build_policy_bundle",
    "build_policy_input",
    "fetch_method_snapshot",
    "fetch_methods_with_context",
    "get_policy_catalog_entries",
    "is_test_source_path",
    "load_iso_rules",
    "normalize_policy_bundle_mapping",
    "normalize_violation_payload",
    "resolve_source_path",
    "serialize_policy_bundle",
    "serialize_policy_input_envelope",
    "validate_graph_generation",
]


def __getattr__(name: str):
    if name in {
        "build_evidence_bundle",
        "build_evidence_bundle_from_source",
        "build_policy_input",
        "fetch_method_snapshot",
        "fetch_methods_with_context",
        "resolve_source_path",
        "validate_graph_generation",
    }:
        from codegraph.policy.runtime import bundles

        return getattr(bundles, name)
    if name in {"get_policy_catalog_entries", "load_iso_rules"}:
        from codegraph.policy.runtime import catalog

        return getattr(catalog, name)
    if name in {
        "build_policy_bundle",
        "normalize_policy_bundle_mapping",
        "serialize_policy_bundle",
        "serialize_policy_input_envelope",
    }:
        from codegraph.policy.runtime import contracts

        return getattr(contracts, name)
    if name == "is_test_source_path":
        from codegraph.policy.runtime import graph_queries

        return getattr(graph_queries, name)
    if name == "normalize_violation_payload":
        from codegraph.policy.runtime import opa

        return getattr(opa, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
