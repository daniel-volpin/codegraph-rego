from __future__ import annotations

from collections.abc import Iterable
from dataclasses import asdict, dataclass
from typing import Any

from codegraph.benchmark_registry import load_policy_registry

SUPPORTED_RULE_RATIONALES = {
    "ISO-A.10-WEAK-HASH": "Bounded weak-hash replacements such as MD5 or SHA-1 to SHA-256 can be applied with minimal local edits.",
    "ISO-A.10-WEAK-RANDOM": "Local randomness upgrades can often be made safely with narrow replacements to SecureRandom-based APIs.",
    "ISO-A.10-WEAK-CRYPTO": "Weak-cipher remediation is available only for explicit literal subcases where a safe minimal replacement is evident.",
}
SAFE_REFUSAL_RULE_IDS = frozenset({"ISO-A.10-WEAK-RANDOM", "ISO-A.10-WEAK-CRYPTO"})


def _build_default_remediation_rule_matrix() -> dict[str, dict[str, Any]]:
    matrix: dict[str, dict[str, Any]] = {}
    for category in load_policy_registry().categories:
        if category.remediation_tier not in {"full", "guarded"}:
            continue
        for rule_id in category.rego_rule_ids:
            matrix[rule_id] = {
                "support_tier": category.remediation_tier,
                "reason_code": "supported_rule_for_auto_fix",
                "strategy": "llm_method_replacement",
                "preview_available": True,
                "verify_available": True,
                "safe_refusal_possible": rule_id in SAFE_REFUSAL_RULE_IDS,
                "rationale": SUPPORTED_RULE_RATIONALES.get(
                    rule_id,
                    "Automatic remediation is enabled for this supported rule.",
                ),
            }
    return matrix


DEFAULT_REMEDIATION_RULE_MATRIX = _build_default_remediation_rule_matrix()

DEFAULT_SUPPORTED_REMEDIATION_RULE_IDS = frozenset(DEFAULT_REMEDIATION_RULE_MATRIX.keys())


@dataclass(frozen=True)
class RemediationCapability:
    supported: bool
    support_tier: str
    reason_code: str
    strategy: str | None
    preview_available: bool
    verify_available: bool
    ui_apply_mode: str
    rationale: str
    safe_refusal_possible: bool


def rule_id_variants(rule_id: str | None) -> list[str]:
    text = str(rule_id or "").strip()
    if not text:
        return []
    variants = [text]
    if text.startswith("ISO-27001-"):
        base = text[len("ISO-27001-") :]
    elif text.startswith("ISO-"):
        base = text[len("ISO-") :]
    else:
        base = text
    for candidate in (base, f"ISO-{base}", f"ISO-27001-{base}"):
        if candidate and candidate not in variants:
            variants.append(candidate)
    return variants


def get_remediation_capability(
    rule_id: str | None,
    *,
    supported_rule_ids: Iterable[str] | None = None,
) -> RemediationCapability:
    if supported_rule_ids is None:
        supported_ids = set(DEFAULT_SUPPORTED_REMEDIATION_RULE_IDS)
        capability_map = dict(DEFAULT_REMEDIATION_RULE_MATRIX)
    else:
        supported_ids = set(supported_rule_ids)
        capability_map = {
            rule_id_value: dict(
                DEFAULT_REMEDIATION_RULE_MATRIX.get(
                    rule_id_value,
                    {
                        "support_tier": "full",
                        "reason_code": "supported_rule_for_auto_fix",
                        "strategy": "llm_method_replacement",
                        "preview_available": True,
                        "verify_available": True,
                        "safe_refusal_possible": False,
                        "rationale": "Automatic remediation is enabled for this supported rule.",
                    },
                )
            )
            for rule_id_value in supported_ids
        }

    for candidate in rule_id_variants(rule_id):
        if candidate in supported_ids:
            meta = capability_map.get(candidate, {})
            return RemediationCapability(
                supported=True,
                support_tier=str(meta.get("support_tier") or "full"),
                reason_code=str(meta.get("reason_code") or "supported_rule_for_auto_fix"),
                strategy=str(meta.get("strategy")) if meta.get("strategy") is not None else None,
                preview_available=bool(meta.get("preview_available", True)),
                verify_available=bool(meta.get("verify_available", True)),
                ui_apply_mode="dry_run",
                rationale=str(meta.get("rationale") or "Automatic remediation is enabled for this supported rule."),
                safe_refusal_possible=bool(meta.get("safe_refusal_possible", False)),
            )

    unsupported_reason = (
        "Automatic remediation is not enabled for this rule because safe bounded transformations are not yet defined."
    )
    if any(candidate == "ISO-A.8-SQL-INJECTION" for candidate in rule_id_variants(rule_id)):
        unsupported_reason = "SQL injection remains explanation-only because safe remediation usually requires cross-layer parameterization refactors."
    if any(candidate == "ISO-A.8-PATH-TRAVERSAL" for candidate in rule_id_variants(rule_id)):
        unsupported_reason = "Path traversal remains manual-review because safe remediation depends on path policy, normalization, and authorization context."
    if any(candidate == "ISO-A.8-CMD-INJECTION" for candidate in rule_id_variants(rule_id)):
        unsupported_reason = "Command injection remains manual-review because safe remediation depends on shell semantics, argument boundaries, and platform-specific behavior."
    if any(candidate == "ISO-A.8-LDAP-INJECTION" for candidate in rule_id_variants(rule_id)):
        unsupported_reason = "LDAP injection remains manual-review because safe remediation depends on query semantics and directory-specific escaping behavior."
    if any(candidate == "ISO-A.8-XPATH-INJECTION" for candidate in rule_id_variants(rule_id)):
        unsupported_reason = "XPath injection remains manual-review because safe remediation depends on parser behavior and application-specific query semantics."
    if any(candidate == "ISO-A.9.4.1" for candidate in rule_id_variants(rule_id)):
        unsupported_reason = "Access-control findings remain manual-review because endpoint semantics cannot be safely inferred from method-local evidence."

    return RemediationCapability(
        supported=False,
        support_tier="manual",
        reason_code="unsupported_rule_for_auto_fix",
        strategy=None,
        preview_available=False,
        verify_available=False,
        ui_apply_mode="dry_run",
        rationale=unsupported_reason,
        safe_refusal_possible=False,
    )


def remediation_capability_dict(
    rule_id: str | None,
    *,
    supported_rule_ids: Iterable[str] | None = None,
) -> dict[str, Any]:
    return asdict(get_remediation_capability(rule_id, supported_rule_ids=supported_rule_ids))
