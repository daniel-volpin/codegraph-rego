"""Policy pack registry and dynamic discovery loader."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from codegraph.benchmark_registry import load_policy_registry
from codegraph.policy.packs.models import PolicyPackSpec, PolicyRuleDefinition

LOGGER = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_POLICY_DIR = _PROJECT_ROOT / "policy"


class PolicyPackRegistry:
    """Registry managing pluggable policy packs and their query entrypoints."""

    def __init__(self) -> None:
        self._packs: dict[str, PolicyPackSpec] = {}
        self._rules_by_id: dict[str, PolicyRuleDefinition] = {}
        self._register_default_iso_pack()
        self._discover_built_in_packs()

    def _discover_built_in_packs(self) -> None:
        """Scan and register pre-packaged compliance policy packs (PCI-DSS, OWASP Top 10, NIST)."""
        packs_dir = DEFAULT_POLICY_DIR / "packs"
        if not packs_dir.is_dir():
            return
        for manifest in sorted(packs_dir.glob("*/manifest.json")):
            try:
                self.load_pack_from_manifest(manifest)
            except Exception as exc:
                LOGGER.warning("Could not load policy pack manifest at %s: %s", manifest, exc)

    def _register_default_iso_pack(self) -> None:
        """Register the default ISO-27001 benchmark compliance pack."""
        try:
            registry = load_policy_registry()
            rules = [
                PolicyRuleDefinition(
                    id=spec.id,
                    control=spec.control,
                    title=spec.title,
                    summary=spec.summary,
                    rego_module=spec.rego_module,
                    rego_rule=spec.rego_rule,
                    evidence_fields=spec.evidence_fields,
                    reference=spec.reference,
                    description=spec.description,
                    alias_ids=spec.alias_ids,
                )
                for spec in registry.rules
            ]
        except Exception as exc:
            LOGGER.warning("Could not pre-populate ISO rules from benchmark registry: %s", exc)
            rules = []

        default_pack = PolicyPackSpec(
            pack_id="iso-27001",
            name="ISO/IEC 27001 Benchmark Security Policy Pack",
            standard="ISO-27001",
            version="1.0.0",
            rego_dir=DEFAULT_POLICY_DIR,
            query_entrypoints=("data.iso27001.violations",),
            enabled=True,
            description="Default security and compliance rules for OWASP Benchmark controls.",
            rules=tuple(rules),
        )
        self.register_pack(default_pack)

    def register_pack(self, pack: PolicyPackSpec) -> None:
        """Register a policy pack and index its rules."""
        self._packs[pack.pack_id] = pack
        for rule in pack.rules:
            self._rules_by_id[rule.id] = rule
            for alias in rule.alias_ids:
                self._rules_by_id[alias] = rule
        LOGGER.info("Registered policy pack %s (v%s) with %d rules", pack.pack_id, pack.version, len(pack.rules))

    def get_pack(self, pack_id: str) -> PolicyPackSpec | None:
        return self._packs.get(pack_id)

    def list_packs(self) -> list[PolicyPackSpec]:
        return list(self._packs.values())

    def get_active_packs(self) -> list[PolicyPackSpec]:
        return [pack for pack in self._packs.values() if pack.enabled]

    def get_active_query_entrypoints(self) -> list[tuple[Path, str]]:
        """Return list of (rego_directory, query_entrypoint) for all active packs."""
        entrypoints: list[tuple[Path, str]] = []
        for pack in self.get_active_packs():
            for query in pack.query_entrypoints:
                entrypoints.append((pack.rego_dir, query))
        return entrypoints

    def get_rule(self, rule_id: str) -> PolicyRuleDefinition | None:
        return self._rules_by_id.get(rule_id)

    def load_pack_from_manifest(self, manifest_path: str | Path) -> PolicyPackSpec:
        """Load and register a policy pack from a JSON manifest file."""
        path = Path(manifest_path).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"Policy pack manifest not found at {path}")

        data = json.loads(path.read_text(encoding="utf-8"))
        rego_dir_str = data.get("rego_dir")
        if rego_dir_str:
            rego_dir = Path(rego_dir_str).resolve()
        else:
            rego_dir = path.parent if any(path.parent.glob("*.rego")) else DEFAULT_POLICY_DIR

        rules = [
            PolicyRuleDefinition(
                id=r["id"],
                control=r.get("control") or r["id"],
                title=r.get("title") or r["id"],
                summary=r.get("summary") or "",
                rego_module=r.get("rego_module") or "main",
                rego_rule=r.get("rego_rule") or "violation",
                category=r.get("category") or "",
                evidence_fields=tuple(r.get("evidence_fields") or ()),
                severity=r.get("severity") or "high",
                reference=r.get("reference") or "",
                description=r.get("description") or "",
                alias_ids=tuple(r.get("alias_ids") or ()),
            )
            for r in data.get("rules", [])
        ]

        pack = PolicyPackSpec(
            pack_id=data["pack_id"],
            name=data.get("name") or data["pack_id"],
            standard=data.get("standard") or "Custom",
            version=data.get("version") or "1.0.0",
            rego_dir=rego_dir,
            query_entrypoints=tuple(data.get("query_entrypoints") or ("data.custom.violations",)),
            enabled=bool(data.get("enabled", True)),
            description=data.get("description") or "",
            rules=tuple(rules),
        )
        self.register_pack(pack)
        return pack


_GLOBAL_REGISTRY: PolicyPackRegistry | None = None


def get_policy_pack_registry() -> PolicyPackRegistry:
    """Return the process-wide singleton policy pack registry."""
    global _GLOBAL_REGISTRY
    if _GLOBAL_REGISTRY is None:
        _GLOBAL_REGISTRY = PolicyPackRegistry()
    return _GLOBAL_REGISTRY
