"""Policy package: OPA/Rego rule evaluation, catalog discovery, taint detection, pluggable packs, and SARIF bridge."""

from __future__ import annotations

from typing import TYPE_CHECKING

from codegraph.policy.sarif import export_findings_to_sarif
from codegraph.policy.taint_graph import TaintPathFinder

if TYPE_CHECKING:
    from codegraph.policy.integration import (
        evaluate_policies,
        get_policy_catalog_entries,
        get_policy_catalog_payload,
        load_iso_rules,
        load_policy_catalog,
    )
    from codegraph.policy.packs import PolicyPackRegistry, get_policy_pack_registry
    from codegraph.policy.sarif_import import import_findings_from_sarif

__all__ = [
    "PolicyPackRegistry",
    "TaintPathFinder",
    "evaluate_policies",
    "export_findings_to_sarif",
    "get_policy_catalog_entries",
    "get_policy_catalog_payload",
    "get_policy_pack_registry",
    "import_findings_from_sarif",
    "load_iso_rules",
    "load_policy_catalog",
]


def __getattr__(name: str):
    if name in {
        "evaluate_policies",
        "get_policy_catalog_entries",
        "get_policy_catalog_payload",
        "load_iso_rules",
        "load_policy_catalog",
    }:
        from codegraph.policy import integration

        return getattr(integration, name)
    if name in {"PolicyPackRegistry", "get_policy_pack_registry"}:
        from codegraph.policy import packs

        return getattr(packs, name)
    if name == "import_findings_from_sarif":
        from codegraph.policy import sarif_import

        return getattr(sarif_import, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
