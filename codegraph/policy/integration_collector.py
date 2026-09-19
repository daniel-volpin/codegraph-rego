from __future__ import annotations

import logging
from typing import Any

from codegraph.common.concurrency import bounded_futures
from codegraph.config import settings
from codegraph.db import shared_neo4j_driver
from codegraph.policy.engines import dedupe_violations, evaluate_all
from codegraph.policy.runtime import catalog as runtime_catalog
from codegraph.policy.runtime import opa as runtime_opa

LOGGER = logging.getLogger(__name__)


def allowed_rule_ids(rule_ids: list[str] | None) -> set[str]:
    return {str(rule_id).strip() for rule_id in (rule_ids or []) if str(rule_id).strip()}


def include_limit_metadata(
    *,
    max_bundles: int | None,
    max_total_violations: int | None,
    max_per_violation_id: int | None,
    rule_ids: list[str] | None,
) -> bool:
    return any(value is not None for value in (max_bundles, max_total_violations, max_per_violation_id, rule_ids))


def bundle_failure(bundle: dict[str, Any], exc: RuntimeError) -> dict[str, Any]:
    return {
        "target_method": bundle.get("target_method"),
        "file_path": bundle.get("file_path"),
        "error": str(exc),
    }


def evaluate_bundles_concurrently(bundles: list[dict[str, Any]]) -> tuple[list[Any], list[dict[str, Any]]]:
    opa_results: list[Any] = [None] * len(bundles)
    failed_bundles: list[dict[str, Any]] = []

    for idx, future in bounded_futures(runtime_opa.evaluate_bundle, bundles, max_workers=settings.policy_workers):
        bundle = bundles[idx]
        try:
            opa_results[idx] = future.result()
        except RuntimeError as exc:
            failed_bundles.append(bundle_failure(bundle, exc))
            LOGGER.warning("OPA evaluation failed for bundle %s: %s", bundle.get("target_method"), exc)

    failed_bundles.sort(key=lambda failure: (str(failure["file_path"]), str(failure["target_method"])))
    return opa_results, failed_bundles


def max_per_rule_reached(
    violation_id: Any,
    violation_counts_by_id: dict[str, int],
    max_per_violation_id: int | None,
) -> bool:
    if violation_id is None:
        return False
    if not isinstance(max_per_violation_id, int) or max_per_violation_id <= 0:
        return False
    return violation_counts_by_id.get(str(violation_id), 0) >= max_per_violation_id


def is_allowed_rule(violation_id: Any, allowed_rules: set[str]) -> bool:
    return not allowed_rules or str(violation_id or "").strip() in allowed_rules


def max_total_reached(total: int, max_total_violations: int | None) -> bool:
    return isinstance(max_total_violations, int) and max_total_violations > 0 and total >= max_total_violations


def collect_violation_responses(
    *,
    bundles: list[dict[str, Any]],
    opa_results: list[Any],
    catalog: dict[str, Any],
    allowed_rules: set[str],
    max_per_violation_id: int | None,
    max_total_violations: int | None,
) -> tuple[list[dict[str, Any]], dict[str, int], int, int]:
    violations: list[dict[str, Any]] = []
    violation_counts_by_id: dict[str, int] = {}
    omitted_findings = 0
    excluded_findings = 0

    for bundle, opa_result in zip(bundles, opa_results):
        for violation in opa_result or []:
            normalized = runtime_opa.normalize_violation_payload(violation, LOGGER)
            if normalized is None:
                continue

            violation_id = normalized.get("violation_id")
            if not is_allowed_rule(violation_id, allowed_rules):
                excluded_findings += 1
                continue
            if max_per_rule_reached(
                violation_id, violation_counts_by_id, max_per_violation_id
            ) or max_total_reached(len(violations), max_total_violations):
                omitted_findings += 1
                continue

            control_meta = runtime_catalog.resolve_catalog_entry(violation_id, catalog)
            violations.append(runtime_opa.build_violation_response(normalized, bundle, control_meta))
            if violation_id is not None:
                key = str(violation_id)
                violation_counts_by_id[key] = violation_counts_by_id.get(key, 0) + 1
    return violations, violation_counts_by_id, omitted_findings, excluded_findings


def collect_engine_violations(
    *,
    allowed_rules: set[str],
    violation_counts_by_id: dict[str, int],
    workspace_root: str | None,
) -> list[dict[str, Any]]:
    def _log(engine_name: str, exc: Exception) -> None:
        LOGGER.error(
            "%s-backed policy evaluation failed; continuing without its findings.",
            engine_name,
            exc_info=exc,
        )

    engine_violations = evaluate_all(
        workspace_root=workspace_root,
        neo4j_driver=shared_neo4j_driver(),
        on_error=_log,
    )

    accepted: list[dict[str, Any]] = []
    for violation in dedupe_violations(engine_violations):
        violation_id = violation.get("violation_id")
        if not is_allowed_rule(violation_id, allowed_rules):
            continue
        accepted.append(violation)
        if violation_id is not None:
            key = str(violation_id)
            violation_counts_by_id[key] = violation_counts_by_id.get(key, 0) + 1
    return accepted
