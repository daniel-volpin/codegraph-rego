"""
Typed Repair Intent IR for bounded Java security remediation planning.
"""

from __future__ import annotations

import logging
from typing import Any

from codegraph.remediation.capabilities import (
    RemediationCapability,
    get_remediation_capability,
)
from codegraph.remediation.contracts import (
    FIX_STRATEGIES,
    resolve_context_source_code,
)
from codegraph.remediation.repair_intent_builders import (
    _DEFAULT_INVARIANTS,
    _RULE_INTENT_KIND,
    _preflight_refusal,
    build_operations,
)
from codegraph.remediation.repair_intent_models import (
    ConstructorReplacementOp,
    ImportAdjustmentOp,
    Invariant,
    InvariantKind,
    LiteralReplacementOp,
    MethodCallReplacementOp,
    RefusalCode,
    RefusalReason,
    RepairIntent,
    RepairIntentKind,
    RepairOperation,
    SourceSpan,
    TransformationSpec,
)

LOGGER = logging.getLogger(__name__)

__all__ = [
    "ConstructorReplacementOp",
    "ImportAdjustmentOp",
    "Invariant",
    "InvariantKind",
    "LiteralReplacementOp",
    "MethodCallReplacementOp",
    "RefusalCode",
    "RefusalReason",
    "RepairIntent",
    "RepairIntentKind",
    "RepairOperation",
    "SourceSpan",
    "TransformationSpec",
    "plan_repair_intent",
]


def plan_repair_intent(
    context: dict[str, Any],
    capability: RemediationCapability | None = None,
    *,
    supported_rule_ids: set[str] | None = None,
) -> RepairIntent:
    rule_id = str(context.get("rule_id") or "")
    target_method = str(context.get("target_method") or "unknown")
    file_path = str(context.get("file_path") or "unknown")

    target = SourceSpan(
        file_path=file_path,
        method_signature=target_method,
    )

    if capability is None:
        capability = get_remediation_capability(
            rule_id,
            supported_rule_ids=supported_rule_ids or FIX_STRATEGIES.keys(),
        )

    if not capability.supported:
        LOGGER.debug("RepairIntent: no_repair for unsupported rule %s (%s)", rule_id, capability.reason_code)
        return RepairIntent(
            kind=RepairIntentKind.NO_REPAIR,
            rule_id=rule_id,
            support_tier="manual",
            target=target,
            refusal=RefusalReason(
                code=RefusalCode.UNSUPPORTED_RULE,
                explanation=capability.rationale,
            ),
        )

    source_code = resolve_context_source_code(context)
    preflight = _preflight_refusal(rule_id, source_code)
    if preflight is not None:
        LOGGER.debug("RepairIntent: no_repair for preflight refusal on %s (%s)", rule_id, preflight.code)
        return RepairIntent(
            kind=RepairIntentKind.NO_REPAIR,
            rule_id=rule_id,
            support_tier=capability.support_tier,
            target=target,
            refusal=preflight,
        )

    strategy = FIX_STRATEGIES.get(rule_id) or {}
    transformation = TransformationSpec(
        objective=str(strategy.get("objective") or "").strip(),
        allowed_transforms=list(strategy.get("allowed_transformations") or []),
        non_goals=list(strategy.get("non_goals") or []),
    )

    kind = _RULE_INTENT_KIND.get(rule_id, RepairIntentKind.LITERAL_REPLACEMENT)
    invariants = list(_DEFAULT_INVARIANTS)
    if kind == RepairIntentKind.CONSTRUCTOR_REPLACEMENT:
        invariants.append(
            Invariant(
                kind=InvariantKind.PRESERVE_TERMINAL_INVOCATION,
                description="Preserve downstream invocation contract when upgrading a constructor chain.",
            )
        )

    operations = build_operations(rule_id, source_code)

    intent = RepairIntent(
        kind=kind,
        rule_id=rule_id,
        support_tier=capability.support_tier,
        target=target,
        transformation=transformation,
        invariants=invariants,
        operations=operations,
    )

    LOGGER.debug(
        "RepairIntent: planned %s for %s (tier=%s, ops=%d)",
        intent.kind,
        rule_id,
        intent.support_tier,
        len(intent.operations),
    )
    return intent
