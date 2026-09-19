from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from codegraph.benchmark_registry_models import (
    BenchmarkCategorySpec,
    PolicyRegistry,
    PolicyRuleSpec,
    RegistryTier,
)
from codegraph.benchmark_registry_validation import (
    first_duplicate as _first_duplicate,
)
from codegraph.benchmark_registry_validation import (
    validate_engine_rule as _validate_engine_rule,
)
from codegraph.benchmark_registry_validation import (
    validate_registry as _validate_registry,
)
from codegraph.benchmark_registry_validation import (
    validate_rule as _validate_rule,
)
from codegraph.benchmark_registry_validation import (
    validate_rule_module as _validate_rule_module,
)

__all__ = [
    "BenchmarkCategorySpec",
    "DEFAULT_POLICY_REGISTRY_PATH",
    "PROJECT_ROOT",
    "PolicyRegistry",
    "PolicyRuleSpec",
    "RegistryTier",
    "_first_duplicate",
    "_validate_engine_rule",
    "_validate_registry",
    "_validate_rule",
    "_validate_rule_module",
    "benchmark_category_payloads",
    "evidence_source_for_rule_id",
    "framework_demo_category_ids",
    "framework_demo_rule_ids",
    "iso_rules_payload_from_registry",
    "load_policy_registry",
    "policy_catalog_entries_from_registry",
    "policy_catalog_payload_from_registry",
    "remediation_tier_by_rule_id",
    "supported_remediation_rule_ids",
]

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY_REGISTRY_PATH = PROJECT_ROOT / "configs" / "benchmark" / "policy_registry.json"


def _read_registry(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"Policy registry at {path} must be a JSON object.")
    return payload


def _string_tuple(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(str(item) for item in value if item)


def _require_mapping(value: Any, *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"Each {label} entry must be a JSON object.")
    return value


def _parse_rule_entry(entry: Any) -> PolicyRuleSpec:
    rule = _require_mapping(entry, label="rule")
    iso_rule = rule.get("iso_rule") or {}
    if not isinstance(iso_rule, dict):
        raise ValueError("Each rule entry must include an 'iso_rule' object.")
    return PolicyRuleSpec(
        id=str(rule.get("id") or ""),
        control=str(rule.get("control") or ""),
        title=str(rule.get("title") or ""),
        reference=str(rule.get("reference") or ""),
        summary=str(rule.get("summary") or ""),
        evidence_fields=_string_tuple(rule.get("evidence_fields")),
        standard=str(iso_rule.get("standard") or ""),
        iso_rule_id=str(iso_rule.get("id") or ""),
        subject=str(iso_rule.get("subject") or ""),
        action=str(iso_rule.get("action") or ""),
        object=str(iso_rule.get("object") or ""),
        conditions=_string_tuple(iso_rule.get("conditions")),
        description=str(iso_rule.get("description") or ""),
        alias_ids=_string_tuple(rule.get("alias_ids")),
        evidence_source=str(rule.get("evidence_source") or "opa"),
        rego_module=str(rule.get("rego_module") or ""),
        rego_rule=str(rule.get("rego_rule") or ""),
        opengrep_rules_dir=str(rule.get("opengrep_rules_dir") or ""),
    )


def _parse_rules(entries: Any) -> tuple[PolicyRuleSpec, ...]:
    if not isinstance(entries, list):
        raise ValueError("Policy registry must define a 'rules' list.")
    return tuple(_parse_rule_entry(entry) for entry in entries)


def _parse_category_entry(entry: Any) -> BenchmarkCategorySpec:
    category = _require_mapping(entry, label="category")
    tier = str(category.get("remediation_tier") or "manual")
    if tier not in {"full", "guarded", "manual"}:
        raise ValueError(f"Unknown remediation tier: {tier}")
    return BenchmarkCategorySpec(
        category_id=str(category.get("category_id") or category.get("id") or ""),
        label=str(category.get("label") or category.get("category_id") or category.get("id") or ""),
        cwes=_string_tuple(category.get("cwes")),
        rego_rule_ids=_string_tuple(category.get("rego_rule_ids") or category.get("rego_rules")),
        control_ids=_string_tuple(category.get("control_ids") or category.get("iso_controls")),
        remediation_tier=tier,
        framework_demo=bool(category.get("framework_demo", False)),
    )


def _parse_categories(entries: Any) -> tuple[BenchmarkCategorySpec, ...]:
    if not isinstance(entries, list):
        raise ValueError("Policy registry must define a 'categories' list.")
    return tuple(_parse_category_entry(entry) for entry in entries)


@lru_cache(maxsize=4)
def load_policy_registry(path: str | None = None) -> PolicyRegistry:
    registry_path = Path(path).resolve() if path else DEFAULT_POLICY_REGISTRY_PATH.resolve()
    payload = _read_registry(registry_path)
    registry = PolicyRegistry(
        rules=_parse_rules(payload.get("rules")),
        categories=_parse_categories(payload.get("categories")),
    )
    return _validate_registry(registry, PROJECT_ROOT)


def benchmark_category_payloads(path: str | None = None) -> list[dict[str, Any]]:
    return [category.as_dict() for category in load_policy_registry(path).categories]


def framework_demo_rule_ids(path: str | None = None) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for category in load_policy_registry(path).categories:
        if not category.framework_demo:
            continue
        for rule_id in category.rego_rule_ids:
            if rule_id in seen:
                continue
            seen.add(rule_id)
            ordered.append(rule_id)
    return ordered


def framework_demo_category_ids(path: str | None = None) -> list[str]:
    return [category.category_id for category in load_policy_registry(path).categories if category.framework_demo]


def remediation_tier_by_rule_id(path: str | None = None) -> dict[str, RegistryTier]:
    mapping: dict[str, RegistryTier] = {}
    for category in load_policy_registry(path).categories:
        for rule_id in category.rego_rule_ids:
            mapping[rule_id] = category.remediation_tier
    return mapping


def supported_remediation_rule_ids(path: str | None = None) -> list[str]:
    return [rule_id for rule_id, tier in remediation_tier_by_rule_id(path).items() if tier in {"full", "guarded"}]


def evidence_source_for_rule_id(rule_id: str | None, path: str | None = None) -> str | None:
    if not rule_id:
        return None
    wanted = str(rule_id).strip()
    for rule in load_policy_registry(path).rules:
        if rule.id == wanted or wanted in rule.alias_ids:
            return rule.evidence_source
    return None


def policy_catalog_entries_from_registry(path: str | None = None) -> list[dict[str, Any]]:
    return [rule.as_catalog_entry() for rule in load_policy_registry(path).rules]


def iso_rules_payload_from_registry(path: str | None = None) -> dict[str, Any]:
    return {"rules": [rule.as_iso_rule_entry() for rule in load_policy_registry(path).rules]}


def policy_catalog_payload_from_registry(path: str | None = None) -> dict[str, Any]:
    return {
        "controls": policy_catalog_entries_from_registry(path),
        "rules": iso_rules_payload_from_registry(path).get("rules", []),
        "benchmark_categories": benchmark_category_payloads(path),
        "framework_demo_rule_ids": framework_demo_rule_ids(path),
    }
