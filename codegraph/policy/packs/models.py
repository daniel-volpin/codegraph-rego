"""Data models and specifications for pluggable policy packs."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class PolicyRuleDefinition:
    """Specification of a single security or compliance rule within a policy pack."""

    id: str
    control: str
    title: str
    summary: str
    rego_module: str
    rego_rule: str
    category: str = ""
    evidence_fields: tuple[str, ...] = ()
    severity: str = "high"
    reference: str = ""
    description: str = ""
    alias_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class PolicyPackSpec:
    """Specification of a pluggable, self-contained OPA/Rego policy pack."""

    pack_id: str
    name: str
    standard: str
    version: str
    rego_dir: Path
    query_entrypoints: tuple[str, ...] = ("data.iso27001.violations",)
    enabled: bool = True
    description: str = ""
    rules: tuple[PolicyRuleDefinition, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "pack_id": self.pack_id,
            "name": self.name,
            "standard": self.standard,
            "version": self.version,
            "rego_dir": str(self.rego_dir),
            "query_entrypoints": list(self.query_entrypoints),
            "enabled": self.enabled,
            "description": self.description,
            "rules_count": len(self.rules),
            "rules": [
                {
                    "id": r.id,
                    "control": r.control,
                    "title": r.title,
                    "summary": r.summary,
                    "rego_module": r.rego_module,
                    "rego_rule": r.rego_rule,
                    "category": r.category,
                    "severity": r.severity,
                    "reference": r.reference,
                    "description": r.description,
                    "alias_ids": list(r.alias_ids),
                }
                for r in self.rules
            ],
        }
