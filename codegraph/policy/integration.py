"""Public policy evaluation façade."""

from __future__ import annotations

import json
import logging
import shutil
from typing import Any

from codegraph.db import shared_neo4j_driver
from codegraph.policy.integration_collector import (
    allowed_rule_ids as _allowed_rule_ids,
)
from codegraph.policy.integration_collector import (
    bundle_failure as _bundle_failure,
)
from codegraph.policy.integration_collector import (
    collect_engine_violations as _collect_engine_violations,
)
from codegraph.policy.integration_collector import (
    collect_violation_responses as _collect_violation_responses,
)
from codegraph.policy.integration_collector import (
    evaluate_bundles_concurrently as _evaluate_bundles_concurrently,
)
from codegraph.policy.integration_collector import (
    include_limit_metadata as _include_limit_metadata,
)
from codegraph.policy.integration_collector import (
    is_allowed_rule as _is_allowed_rule,
)
from codegraph.policy.integration_collector import (
    max_per_rule_reached as _max_per_rule_reached,
)
from codegraph.policy.integration_collector import (
    max_total_reached as _max_total_reached,
)
from codegraph.policy.runtime import bundles as runtime_bundles
from codegraph.policy.runtime import catalog as runtime_catalog
from codegraph.policy.runtime import opa as runtime_opa

LOGGER = logging.getLogger(__name__)

__all__ = [
    "PolicyEvaluator",
    "_allowed_rule_ids",
    "_bundle_failure",
    "_collect_engine_violations",
    "_collect_violation_responses",
    "_evaluate_bundles_concurrently",
    "_include_limit_metadata",
    "_is_allowed_rule",
    "_max_per_rule_reached",
    "_max_total_reached",
    "build_evidence_bundle",
    "build_policy_input",
    "evaluate_bundle",
    "evaluate_policies",
    "get_policy_catalog_entries",
    "get_policy_catalog_payload",
    "load_iso_rules",
    "load_policy_catalog",
    "normalize_violation_payload",
]


def load_policy_catalog() -> dict[str, dict[str, Any]]:
    return runtime_catalog.load_policy_catalog()


def get_policy_catalog_entries() -> list[dict[str, Any]]:
    return runtime_catalog.get_policy_catalog_entries()


def load_iso_rules() -> dict[str, Any]:
    return runtime_catalog.load_iso_rules()


def get_policy_catalog_payload() -> dict[str, Any]:
    return runtime_catalog.get_policy_catalog_payload()


def build_policy_input(
    *,
    max_bundles: int | None = None,
    workspace_root: str | None = None,
) -> dict[str, Any]:
    return runtime_bundles.build_policy_input(max_bundles=max_bundles, workspace_root=workspace_root)


def build_evidence_bundle(
    method_snapshot: dict[str, Any],
    search_service=None,
    method_index: dict[str, dict[str, Any]] | None = None,
    source_path_override: str | None = None,
    resolved_config=None,
) -> dict[str, Any]:
    return runtime_bundles.build_evidence_bundle(
        method_snapshot,
        search_service=search_service,
        method_index=method_index,
        source_path_override=source_path_override,
        resolved_config=resolved_config,
    )


def evaluate_policies(
    *,
    max_bundles: int | None = None,
    max_total_violations: int | None = None,
    max_per_violation_id: int | None = None,
    rule_ids: list[str] | None = None,
    workspace_root: str | None = None,
) -> dict[str, Any]:
    if not shutil.which("opa"):
        return {
            "error": "OPA CLI not found on PATH",
            "hint": "Install OPA: https://www.openpolicyagent.org/docs/latest/#running-opa",
        }

    try:
        policy_input = build_policy_input(max_bundles=max_bundles, workspace_root=workspace_root)
    except ValueError as exc:
        return {
            "error": f"policy_evidence_unavailable: {exc}",
            "hint": (
                "The active graph revision references source that cannot be read. "
                "Re-ingest the workspace so the graph and its source agree."
            ),
            "workspace_root": workspace_root,
        }
    bundles = policy_input.get("bundles") or []
    catalog = load_policy_catalog()
    rules_catalog = load_iso_rules()
    allowed_rule_ids = _allowed_rule_ids(rule_ids)
    include_limit_metadata = _include_limit_metadata(
        max_bundles=max_bundles,
        max_total_violations=max_total_violations,
        max_per_violation_id=max_per_violation_id,
        rule_ids=rule_ids,
    )

    opa_results, failed_bundles = _evaluate_bundles_concurrently(bundles)
    violations, violation_counts_by_id, omitted_findings, excluded_findings = _collect_violation_responses(
        bundles=bundles,
        opa_results=opa_results,
        catalog=catalog,
        allowed_rules=allowed_rule_ids,
        max_per_violation_id=max_per_violation_id,
        max_total_violations=max_total_violations,
    )
    violations.extend(
        _collect_engine_violations(
            allowed_rules=allowed_rule_ids,
            violation_counts_by_id=violation_counts_by_id,
            workspace_root=workspace_root,
        )
    )

    opa_runs = len(bundles)
    failed_count = len(failed_bundles)
    status = "failed" if failed_count and failed_count == opa_runs else "partial" if failed_count else "complete"
    truncated = omitted_findings > 0
    response: dict[str, Any] = {
        "violations": violations,
        "rules_catalog": rules_catalog,
        "catalog": get_policy_catalog_entries(),
        "opa_runs": opa_runs,
        "bundle_count": len(bundles),
        "evaluation": {
            "status": status,
            "attempted_bundles": opa_runs,
            "evaluated_bundles": opa_runs - failed_count,
            "failed_bundles": failed_count,
            "omitted_findings": omitted_findings,
            "excluded_findings": excluded_findings,
            "truncated": truncated,
            "scope_limited": max_bundles is not None,
            "rule_ids": sorted(allowed_rule_ids),
        },
    }
    if status == "failed":
        response["error"] = "OPA evaluation failed for every selected bundle"
    if failed_bundles:
        response["failed_bundles"] = failed_bundles
        response["failed_bundle_count"] = len(failed_bundles)
    if include_limit_metadata:
        response.update(
            {
                "truncated": truncated,
                "limits": {
                    "max_bundles": max_bundles,
                    "max_total_violations": max_total_violations,
                    "max_per_violation_id": max_per_violation_id,
                    "rule_ids": sorted(allowed_rule_ids) if allowed_rule_ids else None,
                    "workspace_root": workspace_root,
                },
                "violation_counts_by_id": violation_counts_by_id,
            }
        )
    return response


def evaluate_bundle(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    return runtime_opa.evaluate_bundle(bundle)


def normalize_violation_payload(payload: Any) -> dict[str, Any] | None:
    return runtime_opa.normalize_violation_payload(payload, LOGGER)


class PolicyEvaluator:
    """Evaluate policies against a canonical method key."""

    def __init__(self) -> None:
        self._catalog = load_policy_catalog()
        self._rules = load_iso_rules()

    def evaluate(self, method_key: str, *, source_path_override: str | None = None) -> dict[str, Any]:
        snapshot = runtime_bundles.fetch_method_snapshot(shared_neo4j_driver(), method_key)
        if not snapshot:
            return {
                "method_key": method_key,
                "target_method": None,
                "violations": [],
                "error": "method_not_found",
            }
        bundle = build_evidence_bundle(
            snapshot,
            runtime_bundles.load_hybrid_search(),
            source_path_override=source_path_override,
            resolved_config=runtime_bundles.resolve_workspace_config(),
        )
        try:
            opa_output = runtime_opa.evaluate_bundle(bundle)
        except RuntimeError as exc:
            return {
                "method_key": method_key,
                "target_method": snapshot["signature"],
                "violations": [],
                "error": str(exc),
            }
        catalog = self._catalog
        violations: list[dict[str, Any]] = []
        for violation in opa_output:
            normalized = normalize_violation_payload(violation)
            if normalized is None:
                continue
            violation_id = normalized.get("violation_id")
            control_meta = runtime_catalog.resolve_catalog_entry(violation_id, catalog)
            violations.append(runtime_opa.build_violation_response(normalized, bundle, control_meta))
        return {
            "method_key": method_key,
            "target_method": snapshot["signature"],
            "violations": violations,
            "rules_catalog": self._rules,
            "catalog": get_policy_catalog_entries(),
        }

    def trace(self, method_key: str, *, source_path_override: str | None = None) -> dict[str, Any]:
        snapshot = runtime_bundles.fetch_method_snapshot(shared_neo4j_driver(), method_key)
        if not snapshot:
            return {}
        bundle = build_evidence_bundle(
            snapshot,
            runtime_bundles.load_hybrid_search(),
            source_path_override=source_path_override,
            resolved_config=runtime_bundles.resolve_workspace_config(),
        )
        try:
            return runtime_opa.evaluate_package_root(bundle)
        except RuntimeError:
            return {}


if __name__ == "__main__":
    print(json.dumps(evaluate_policies(), indent=2))
