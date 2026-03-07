from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Iterable

DEFAULT_SUPPORTED_REMEDIATION_RULE_IDS = frozenset(
    {
        "ISO-A.10-WEAK-HASH",
        "ISO-A.10-WEAK-CRYPTO",
    }
)


@dataclass(frozen=True)
class RemediationCapability:
    supported: bool
    reason_code: str
    strategy: str | None
    preview_available: bool
    verify_available: bool
    ui_apply_mode: str


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
    supported_ids = set(supported_rule_ids or DEFAULT_SUPPORTED_REMEDIATION_RULE_IDS)
    supported = any(candidate in supported_ids for candidate in rule_id_variants(rule_id))
    if supported:
        return RemediationCapability(
            supported=True,
            reason_code="supported_rule_for_auto_fix",
            strategy="llm_method_replacement",
            preview_available=True,
            verify_available=True,
            ui_apply_mode="dry_run",
        )
    return RemediationCapability(
        supported=False,
        reason_code="unsupported_rule_for_auto_fix",
        strategy=None,
        preview_available=False,
        verify_available=False,
        ui_apply_mode="dry_run",
    )


def remediation_capability_dict(
    rule_id: str | None,
    *,
    supported_rule_ids: Iterable[str] | None = None,
) -> dict[str, Any]:
    return asdict(get_remediation_capability(rule_id, supported_rule_ids=supported_rule_ids))
