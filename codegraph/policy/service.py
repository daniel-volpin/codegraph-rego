from __future__ import annotations

from typing import Any, Dict, List

from codegraph.policy.integration import evaluate_policies, get_policy_catalog_entries


def evaluate() -> Dict[str, Any]:
    """Run OPA evaluation and return the enriched result dictionary."""
    return evaluate_policies()


def catalog() -> List[Dict[str, Any]]:
    """Return policy catalog entries for UI consumption."""
    return get_policy_catalog_entries()
