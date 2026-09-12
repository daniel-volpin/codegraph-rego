from __future__ import annotations

from collections.abc import Iterable
from dataclasses import asdict, dataclass
from functools import lru_cache
from typing import Any

from codegraph.benchmark_registry import load_policy_registry

SUPPORTED_RULE_RATIONALES = {
    "ISO-A.10-WEAK-HASH": "Bounded weak-hash replacements such as MD5 or SHA-1 to SHA-256 can be applied with minimal local edits.",
    "ISO-A.10-WEAK-RANDOM": "Local randomness upgrades can often be made safely with narrow replacements to SecureRandom-based APIs.",
    "ISO-A.10-WEAK-CRYPTO": "Weak-cipher remediation replaces legacy ciphers (DES/RC4) with AES-GCM or approved algorithms with 3-gate verification.",
    "ISO-A.8-SQL-INJECTION": "SQL injection remediation transforms dynamic SQL concatenations into parameterized PreparedStatements with 3-gate safety verification.",
    "ISO-A.8-PATH-TRAVERSAL": "Path traversal remediation applies canonical directory normalization and boundary containment checks.",
    "ISO-A.8-CMD-INJECTION": "Command injection remediation replaces shell concatenation with structured ProcessBuilder argument arrays.",
    "ISO-A.8-LDAP-INJECTION": "LDAP injection remediation applies RFC-compliant filter escaping or parameterized search constraints.",
    "ISO-A.8-XPATH-INJECTION": "XPath injection remediation binds external parameters via XPathVariableResolver to prevent query manipulation.",
    "ISO-A.9.4.1": "Access-control remediation adds Spring Security access control annotations and authentication guard checks.",
    "ISO-A.12.4.1": "Logging and monitoring remediation inserts structured security audit events using standard logging frameworks.",
}
SAFE_REFUSAL_RULE_IDS = frozenset({
    "ISO-A.10-WEAK-RANDOM",
    "ISO-A.10-WEAK-CRYPTO",
    "ISO-A.8-SQL-INJECTION",
    "ISO-A.8-PATH-TRAVERSAL",
    "ISO-A.8-CMD-INJECTION",
    "ISO-A.8-LDAP-INJECTION",
    "ISO-A.8-XPATH-INJECTION",
    "ISO-A.9.4.1",
    "ISO-A.12.4.1",
})


# The default matrix derives from the benchmark policy registry on disk, so it
# is loaded lazily: importing this module (which policy runtime code does on
# every violation response) must not perform file I/O or fail on a missing
# registry.
@lru_cache(maxsize=1)
def default_remediation_rule_matrix() -> dict[str, dict[str, Any]]:
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


def default_supported_remediation_rule_ids() -> frozenset[str]:
    return frozenset(default_remediation_rule_matrix().keys())


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
    default_matrix = default_remediation_rule_matrix()
    if supported_rule_ids is not None:
        supported_ids = set(supported_rule_ids)
        for candidate in rule_id_variants(rule_id):
            if candidate in supported_ids:
                meta = default_matrix.get(candidate, {})
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
        return RemediationCapability(
            supported=False,
            support_tier="manual",
            reason_code="unsupported_rule_for_auto_fix",
            strategy=None,
            preview_available=False,
            verify_available=False,
            ui_apply_mode="dry_run",
            rationale="Automatic remediation is not enabled for this rule under the requested strategy set.",
            safe_refusal_possible=False,
        )

    for candidate in rule_id_variants(rule_id):
        if candidate in default_matrix:
            meta = default_matrix[candidate]
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

    # Imported findings can only enter automatic remediation when an installed
    # policy rule can verify the candidate locally.  Advertising arbitrary
    # external rule IDs as guarded would make the fail-closed OPA gate
    # impossible to satisfy.
    return RemediationCapability(
        supported=False,
        support_tier="manual",
        reason_code="unsupported_rule_for_auto_fix",
        strategy=None,
        preview_available=False,
        verify_available=False,
        ui_apply_mode="dry_run",
        rationale="Automatic remediation requires a registered rule with candidate-local policy verification.",
        safe_refusal_possible=False,
    )


def remediation_capability_dict(
    rule_id: str | None,
    *,
    supported_rule_ids: Iterable[str] | None = None,
) -> dict[str, Any]:
    return asdict(get_remediation_capability(rule_id, supported_rule_ids=supported_rule_ids))
