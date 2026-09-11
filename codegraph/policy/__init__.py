"""Policy package: OPA/Rego rule evaluation, catalog discovery, taint detection, and SARIF export."""

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

__all__ = [
    "TaintPathFinder",
    "evaluate_policies",
    "export_findings_to_sarif",
    "get_policy_catalog_entries",
    "get_policy_catalog_payload",
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
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
