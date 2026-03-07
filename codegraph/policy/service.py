from __future__ import annotations

from typing import Any, Dict, List

from codegraph.policy.integration import evaluate_policies, get_policy_catalog_entries


def evaluate(
    *,
    max_bundles: int | None = None,
    max_total_violations: int | None = None,
    max_per_violation_id: int | None = None,
    rule_ids: list[str] | None = None,
) -> Dict[str, Any]:
    """Run OPA evaluation and return the enriched result dictionary."""
    return evaluate_policies(
        max_bundles=max_bundles,
        max_total_violations=max_total_violations,
        max_per_violation_id=max_per_violation_id,
        rule_ids=rule_ids,
    )


def catalog() -> List[Dict[str, Any]]:
    """Return policy catalog entries for UI consumption."""
    return get_policy_catalog_entries()
