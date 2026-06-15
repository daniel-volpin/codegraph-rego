"""Public policy evaluation façade."""

from __future__ import annotations

import json
import logging
import os
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from codegraph.db import get_neo4j_driver
from codegraph.policy.runtime import bundles as runtime_bundles
from codegraph.policy.runtime import catalog as runtime_catalog
from codegraph.policy.runtime import opa as runtime_opa

LOGGER = logging.getLogger(__name__)


def _load_hybrid_search():
    return runtime_bundles.load_hybrid_search()


def _is_test_source_path(file_path: Any) -> bool:
    return runtime_bundles.is_test_source_path(file_path)


def load_policy_catalog() -> dict[str, dict[str, Any]]:
    return runtime_catalog.load_policy_catalog()


def get_policy_catalog_entries() -> list[dict[str, Any]]:
    return runtime_catalog.get_policy_catalog_entries()


def _resolve_catalog_entry(violation_id: Any, catalog: dict[str, dict[str, Any]]) -> dict[str, Any] | None:
    return runtime_catalog.resolve_catalog_entry(violation_id, catalog)


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


def _fetch_methods_with_context(
    driver,
    *,
    max_bundles: int | None = None,
    workspace_root: str | None = None,
) -> list[dict[str, Any]]:
    return runtime_bundles.fetch_methods_with_context(
        driver,
        max_bundles=max_bundles,
        workspace_root=workspace_root,
    )


def _fetch_method_snapshot(driver, method_signature: str) -> dict[str, Any] | None:
    return runtime_bundles.fetch_method_snapshot(driver, method_signature)


def build_evidence_bundle(
    method_snapshot: dict[str, Any],
    search_service=None,
    method_index: dict[str, dict[str, Any]] | None = None,
    source_path_override: str | None = None,
) -> dict[str, Any]:
    return runtime_bundles.build_evidence_bundle(
        method_snapshot,
        search_service=search_service,
        method_index=method_index,
        source_path_override=source_path_override,
    )


def _normalize_violation_payload(payload: Any) -> dict[str, Any] | None:
    return runtime_opa.normalize_violation_payload(payload, LOGGER)


def _build_violation_response(
    normalized: dict[str, Any],
    bundle: dict[str, Any],
    control_meta: dict[str, Any] | None,
) -> dict[str, Any]:
    return runtime_opa.build_violation_response(normalized, bundle, control_meta)


def _allowed_rule_ids(rule_ids: list[str] | None) -> set[str]:
    return {str(rule_id).strip() for rule_id in (rule_ids or []) if str(rule_id).strip()}


def _include_limit_metadata(
    *,
    max_bundles: int | None,
    max_total_violations: int | None,
    max_per_violation_id: int | None,
    rule_ids: list[str] | None,
) -> bool:
    return any(value is not None for value in (max_bundles, max_total_violations, max_per_violation_id, rule_ids))


def _bundle_failure(bundle: dict[str, Any], exc: RuntimeError) -> dict[str, Any]:
    return {
        "target_method": bundle.get("target_method"),
        "file_path": bundle.get("file_path"),
        "error": str(exc),
    }


def _evaluate_bundles_concurrently(bundles: list[dict[str, Any]]) -> tuple[list[Any], list[dict[str, Any]]]:
    workers = min(32, (os.cpu_count() or 4) + 4)
    opa_results: list[Any] = [None] * len(bundles)
    failed_bundles: list[dict[str, Any]] = []

    with ThreadPoolExecutor(max_workers=workers) as pool:
        future_to_idx = {pool.submit(_evaluate_bundle, bundle): idx for idx, bundle in enumerate(bundles)}
        for future in as_completed(future_to_idx):
            idx = future_to_idx[future]
            bundle = bundles[idx]
            try:
                opa_results[idx] = future.result()
            except RuntimeError as exc:
                failed_bundles.append(_bundle_failure(bundle, exc))
                LOGGER.warning("OPA evaluation failed for bundle %s: %s", bundle.get("target_method"), exc)

    return opa_results, failed_bundles


def _max_per_rule_reached(
    violation_id: Any,
    violation_counts_by_id: dict[str, int],
    max_per_violation_id: int | None,
) -> bool:
    if violation_id is None:
        return False
    if not isinstance(max_per_violation_id, int) or max_per_violation_id <= 0:
        return False
    return violation_counts_by_id.get(str(violation_id), 0) >= max_per_violation_id


def _is_allowed_rule(violation_id: Any, allowed_rule_ids: set[str]) -> bool:
    return not allowed_rule_ids or str(violation_id or "").strip() in allowed_rule_ids


def _max_total_reached(total: int, max_total_violations: int | None) -> bool:
    return isinstance(max_total_violations, int) and max_total_violations > 0 and total >= max_total_violations


def _collect_violation_responses(
    *,
    bundles: list[dict[str, Any]],
    opa_results: list[Any],
    catalog: dict[str, Any],
    allowed_rule_ids: set[str],
    max_per_violation_id: int | None,
    max_total_violations: int | None,
) -> tuple[list[dict[str, Any]], dict[str, int], bool]:
    violations: list[dict[str, Any]] = []
    violation_counts_by_id: dict[str, int] = {}

    for bundle, opa_result in zip(bundles, opa_results):
        for violation in opa_result or []:
            normalized = _normalize_violation_payload(violation)
            if normalized is None:
                continue

            violation_id = normalized.get("violation_id")
            if not _is_allowed_rule(violation_id, allowed_rule_ids):
                continue
            if _max_per_rule_reached(violation_id, violation_counts_by_id, max_per_violation_id):
                continue

            control_meta = _resolve_catalog_entry(violation_id, catalog)
            violations.append(_build_violation_response(normalized, bundle, control_meta))
            if violation_id is not None:
                key = str(violation_id)
                violation_counts_by_id[key] = violation_counts_by_id.get(key, 0) + 1
            if _max_total_reached(len(violations), max_total_violations):
                return violations, violation_counts_by_id, True

    return violations, violation_counts_by_id, False


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

    policy_input = build_policy_input(max_bundles=max_bundles, workspace_root=workspace_root)
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
    violations, violation_counts_by_id, truncated = _collect_violation_responses(
        bundles=bundles,
        opa_results=opa_results,
        catalog=catalog,
        allowed_rule_ids=allowed_rule_ids,
        max_per_violation_id=max_per_violation_id,
        max_total_violations=max_total_violations,
    )

    opa_runs = len(bundles)
    response: dict[str, Any] = {
        "violations": violations,
        "rules_catalog": rules_catalog,
        "catalog": get_policy_catalog_entries(),
        "opa_runs": opa_runs,
        "bundle_count": len(bundles),
    }
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
    """
    Public wrapper to evaluate a single method bundle with OPA. This reuses the
    same query and policy directory as the main evaluation path, but accepts an
    in-memory bundle (e.g., for virtual remediation previews).
    """
    return _evaluate_bundle(bundle)


def normalize_violation_payload(payload: Any) -> dict[str, Any] | None:
    """Public helper to coerce OPA outputs into a dict or return None."""
    return _normalize_violation_payload(payload)


def _evaluate_bundle(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    return runtime_opa.evaluate_bundle(bundle)


def _evaluate_package_root(bundle: dict[str, Any], package: str = "data.iso27001") -> dict[str, Any]:
    return runtime_opa.evaluate_package_root(bundle, package=package)


class PolicyEvaluator:
    """Evaluate policies against a single method signature."""

    def __init__(self) -> None:
        self._catalog = load_policy_catalog()
        self._rules = load_iso_rules()

    def evaluate(self, method_signature: str, *, source_path_override: str | None = None) -> dict[str, Any]:
        driver = get_neo4j_driver()
        try:
            snapshot = _fetch_method_snapshot(driver, method_signature)
        finally:
            driver.close()
        if not snapshot:
            return {
                "target_method": method_signature,
                "violations": [],
                "error": "method_not_found",
            }
        bundle = build_evidence_bundle(snapshot, _load_hybrid_search(), source_path_override=source_path_override)
        try:
            opa_output = _evaluate_bundle(bundle)
        except RuntimeError as exc:
            return {
                "target_method": method_signature,
                "violations": [],
                "error": str(exc),
            }
        catalog = self._catalog
        violations: list[dict[str, Any]] = []
        for violation in opa_output:
            normalized = _normalize_violation_payload(violation)
            if normalized is None:
                continue
            violation_id = normalized.get("violation_id")
            control_meta = _resolve_catalog_entry(violation_id, catalog)
            violations.append(_build_violation_response(normalized, bundle, control_meta))
        return {
            "target_method": method_signature,
            "violations": violations,
            "rules_catalog": self._rules,
            "catalog": get_policy_catalog_entries(),
        }

    def trace(self, method_signature: str, *, source_path_override: str | None = None) -> dict[str, Any]:
        """Shadow trace path: evaluates the bundle via package root to extract intermediate predicate definitions."""
        driver = get_neo4j_driver()
        try:
            snapshot = _fetch_method_snapshot(driver, method_signature)
        finally:
            driver.close()
        if not snapshot:
            return {}
        bundle = build_evidence_bundle(snapshot, _load_hybrid_search(), source_path_override=source_path_override)
        try:
            return _evaluate_package_root(bundle)
        except RuntimeError:
            return {}


if __name__ == "__main__":
    print(json.dumps(evaluate_policies(), indent=2))
