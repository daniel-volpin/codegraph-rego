from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

RegistryTier = Literal["full", "guarded", "manual"]


@dataclass(frozen=True)
class PolicyRuleSpec:
    id: str
    control: str
    title: str
    reference: str
    summary: str
    evidence_fields: tuple[str, ...]
    standard: str
    iso_rule_id: str
    subject: str
    action: str
    object: str
    conditions: tuple[str, ...]
    description: str
    alias_ids: tuple[str, ...] = ()
    evidence_source: str = "opa"
    rego_module: str = ""
    rego_rule: str = ""
    opengrep_rules_dir: str = ""

    def as_catalog_entry(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "id": self.id,
            "control": self.control,
            "title": self.title,
            "reference": self.reference,
            "summary": self.summary,
            "evidence_source": self.evidence_source,
            "evidence_fields": list(self.evidence_fields),
        }
        if self.evidence_source == "opa":
            payload["rego_module"] = self.rego_module
            payload["rego_rule"] = self.rego_rule
        elif self.opengrep_rules_dir:
            payload["opengrep_rules_dir"] = self.opengrep_rules_dir
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
