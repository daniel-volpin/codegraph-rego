from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

from codegraph.policy.runtime.contracts import EVIDENCE_FIELD_ALIAS_MAP

RegistryTier = Literal["full", "guarded", "manual"]

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY_REGISTRY_PATH = PROJECT_ROOT / "configs" / "benchmark" / "policy_registry.json"


@dataclass(frozen=True)
class PolicyRuleSpec:
    id: str
    control: str
    title: str
    reference: str
    summary: str
    rego_module: str
    rego_rule: str
    evidence_fields: tuple[str, ...]
    standard: str
    iso_rule_id: str
    subject: str
    action: str
    object: str
    conditions: tuple[str, ...]
    description: str
    alias_ids: tuple[str, ...] = ()

    def as_catalog_entry(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "id": self.id,
            "control": self.control,
            "title": self.title,
            "reference": self.reference,
            "summary": self.summary,
            "rego_module": self.rego_module,
            "rego_rule": self.rego_rule,
            "evidence_fields": list(self.evidence_fields),
        }
        if self.alias_ids:
            payload["alias_ids"] = list(self.alias_ids)
        return payload

    def as_iso_rule_entry(self) -> dict[str, Any]:
        return {
            "standard": self.standard,
            "id": self.iso_rule_id,
            "subject": self.subject,
            "action": self.action,
            "object": self.object,
            "conditions": list(self.conditions),
            "description": self.description,
        }


@dataclass(frozen=True)
class BenchmarkCategorySpec:
    category_id: str
    label: str
    cwes: tuple[str, ...]
    rego_rule_ids: tuple[str, ...]
    control_ids: tuple[str, ...]
    remediation_tier: RegistryTier
    framework_demo: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "category_id": self.category_id,
            "label": self.label,
            "cwes": list(self.cwes),
            "rego_rule_ids": list(self.rego_rule_ids),
            "control_ids": list(self.control_ids),
            "remediation_tier": self.remediation_tier,
            "framework_demo": self.framework_demo,
        }


@dataclass(frozen=True)
class PolicyRegistry:
    rules: tuple[PolicyRuleSpec, ...]
    categories: tuple[BenchmarkCategorySpec, ...]


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
        rego_module=str(rule.get("rego_module") or ""),
        rego_rule=str(rule.get("rego_rule") or ""),
        evidence_fields=_string_tuple(rule.get("evidence_fields")),
        standard=str(iso_rule.get("standard") or ""),
        iso_rule_id=str(iso_rule.get("id") or ""),
        subject=str(iso_rule.get("subject") or ""),
        action=str(iso_rule.get("action") or ""),
        object=str(iso_rule.get("object") or ""),
        conditions=_string_tuple(iso_rule.get("conditions")),
        description=str(iso_rule.get("description") or ""),
        alias_ids=_string_tuple(rule.get("alias_ids")),
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


def _first_duplicate(values: list[str]) -> str | None:
    seen: set[str] = set()
    for value in values:
        if not value:
            continue
        if value in seen:
            return value
        seen.add(value)
    return None


def _validate_rule_module(rule: PolicyRuleSpec) -> None:
    rego_module_path = (PROJECT_ROOT / rule.rego_module).resolve()
    if rego_module_path.suffix != ".rego":
        raise ValueError(f"Policy registry rule {rule.id} must reference a .rego module: {rule.rego_module}")
    if PROJECT_ROOT.resolve() not in rego_module_path.parents:
        raise ValueError(f"Policy registry rule {rule.id} references a module outside the repository.")
    if not rego_module_path.is_file():
        raise ValueError(f"Policy registry rule {rule.id} references a missing module: {rule.rego_module}")


def _validate_rule(rule: PolicyRuleSpec, *, rule_ids: set[str], alias_ids: set[str], iso_rule_ids: set[str]) -> None:
    if not rule.id:
        raise ValueError("Policy registry rules must include a non-empty id.")
    if not rule.iso_rule_id:
        raise ValueError(f"Policy registry rule {rule.id} must include a non-empty ISO rule id.")
    if rule.iso_rule_id in iso_rule_ids:
        raise ValueError(f"Policy registry contains duplicate ISO rule id: {rule.iso_rule_id}")
    iso_rule_ids.add(rule.iso_rule_id)
    _validate_rule_module(rule)

    for evidence_field in rule.evidence_fields:
        if evidence_field not in EVIDENCE_FIELD_ALIAS_MAP:
            raise ValueError(f"Policy registry rule {rule.id} references an unknown evidence field: {evidence_field}")

    for alias in rule.alias_ids:
        if alias in rule_ids:
            raise ValueError(f"Policy registry alias {alias} collides with a rule id.")
        if alias in alias_ids:
            raise ValueError(f"Policy registry contains duplicate alias id: {alias}")
        alias_ids.add(alias)


def _validate_registry(registry: PolicyRegistry) -> PolicyRegistry:
    all_rule_ids = [rule.id for rule in registry.rules]
    duplicate_rule_id = _first_duplicate(all_rule_ids)
    if duplicate_rule_id:
        raise ValueError(f"Policy registry contains duplicate rule id: {duplicate_rule_id}")

    rule_ids = set(all_rule_ids)
    alias_ids: set[str] = set()
    iso_rule_ids: set[str] = set()
    category_ids: set[str] = set()

    for rule in registry.rules:
        _validate_rule(rule, rule_ids=rule_ids, alias_ids=alias_ids, iso_rule_ids=iso_rule_ids)

    for category in registry.categories:
        if not category.category_id:
            raise ValueError("Policy registry categories must include a non-empty category id.")
        if category.category_id in category_ids:
            raise ValueError(f"Policy registry contains duplicate category id: {category.category_id}")
        category_ids.add(category.category_id)

    missing = sorted(
        rule_id for category in registry.categories for rule_id in category.rego_rule_ids if rule_id not in rule_ids
    )
    if missing:
        raise ValueError(f"Policy registry categories reference unknown rule ids: {missing}")
    return registry


@lru_cache(maxsize=4)
def load_policy_registry(path: str | None = None) -> PolicyRegistry:
    registry_path = Path(path).resolve() if path else DEFAULT_POLICY_REGISTRY_PATH.resolve()
    payload = _read_registry(registry_path)
    registry = PolicyRegistry(
        rules=_parse_rules(payload.get("rules")),
        categories=_parse_categories(payload.get("categories")),
    )
    return _validate_registry(registry)


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
