from __future__ import annotations

from pathlib import Path
from typing import Any

from codegraph.config import settings
from codegraph.db import shared_neo4j_driver
from codegraph.policy.integration import evaluate_policies, get_policy_catalog_payload
from codegraph.policy.packs.loader import get_policy_pack_registry
from codegraph.policy.sarif import export_findings_to_sarif
from codegraph.policy.sarif_import import import_findings_from_sarif


def evaluate(
    *,
    max_bundles: int | None = None,
    max_total_violations: int | None = None,
    max_per_violation_id: int | None = None,
    rule_ids: list[str] | None = None,
    workspace_root: str | None = None,
) -> dict[str, Any]:
    """Run OPA evaluation and return the enriched result dictionary."""
    return evaluate_policies(
        max_bundles=max_bundles,
        max_total_violations=max_total_violations,
        max_per_violation_id=max_per_violation_id,
        rule_ids=rule_ids,
        workspace_root=workspace_root,
    )


def export_sarif(*, workspace_root: str | None = None, rule_ids: list[str] | None = None) -> dict[str, Any]:
    """Run policy evaluation and export findings as a standard SARIF v2.1.0 document."""
    res = evaluate(workspace_root=workspace_root, rule_ids=rule_ids)
    violations = res.get("violations") or []
    return export_findings_to_sarif(violations, workspace_root=workspace_root)


def import_sarif(sarif_data: str | dict[str, Any], *, workspace_root: str | None = None) -> list[dict[str, Any]]:
    """Ingest external SARIF 2.1.0 findings and ground them against Neo4j AST method identities."""
    try:
        driver = shared_neo4j_driver()
    except Exception:
        driver = None
    return import_findings_from_sarif(
        sarif_data,
        workspace_root=Path(workspace_root or settings.upload_dir).resolve().as_posix(),
        neo4j_driver=driver,
    )


def list_policy_packs() -> list[dict[str, Any]]:
    """List all registered pluggable policy packs and active rule counts."""
    registry = get_policy_pack_registry()
    return [pack.to_dict() for pack in registry.list_packs()]


def register_policy_pack_manifest(manifest_path: str | Path) -> dict[str, Any]:
    """Load and register a policy pack from a manifest file."""
    registry = get_policy_pack_registry()
    pack = registry.load_pack_from_manifest(manifest_path)
    return pack.to_dict()


def catalog() -> dict[str, Any]:
    """Return policy catalog metadata for UI consumption."""
    return get_policy_catalog_payload()
