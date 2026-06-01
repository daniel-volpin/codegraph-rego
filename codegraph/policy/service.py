from __future__ import annotations

import os
from typing import Any

from codegraph.config import settings
from codegraph.policy.integration import evaluate_policies, get_policy_catalog_payload


def evaluate(
    *,
    max_bundles: int | None = None,
    max_total_violations: int | None = None,
    max_per_violation_id: int | None = None,
    rule_ids: list[str] | None = None,
    workspace_root: str | None = None,
) -> dict[str, Any]:
    """Run OPA evaluation and return the enriched result dictionary."""
    resolved_workspace_root = workspace_root
    if resolved_workspace_root is None:
        resolved_workspace_root = os.path.abspath(settings.upload_dir)
    return evaluate_policies(
        max_bundles=max_bundles,
        max_total_violations=max_total_violations,
        max_per_violation_id=max_per_violation_id,
        rule_ids=rule_ids,
        workspace_root=resolved_workspace_root,
    )


def catalog() -> dict[str, Any]:
    """Return policy catalog metadata for UI consumption."""
    return get_policy_catalog_payload()
