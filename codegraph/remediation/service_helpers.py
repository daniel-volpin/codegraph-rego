from __future__ import annotations

from typing import Any

from codegraph.config import settings
from codegraph.remediation.capabilities import get_remediation_capability, rule_id_variants
from codegraph.remediation.confidence import ConfidenceFeatures, assess_remediation_confidence
from codegraph.remediation.contracts import (
    AGENTIC_FIX_STRATEGIES,
    build_no_fix_response,
    preflight_unsupported_reason,
    resolve_context_source_code,
)


def has_graph_context(context: dict[str, Any]) -> bool:
    graph_context = ((context.get("evidence") or {}).get("graph_context")) or {}
    if not isinstance(graph_context, dict):
        return False
    keys = ("annotations", "uses_fields", "calls", "callers")
    return any(bool(graph_context.get(key)) for key in keys)


def build_confidence(
    *,
    context: dict[str, Any],
    support_tier: str,
    decision: str,
    structured_valid: bool,
    attempt_count: int,
) -> dict[str, Any]:
    assessment = assess_remediation_confidence(
        ConfidenceFeatures(
            support_tier=support_tier,
            decision=decision,
            structured_valid=structured_valid,
            has_exact_method_source=bool(context.get("exact_method_source")),
            has_graph_context=has_graph_context(context),
            attempt_count=max(1, int(attempt_count)),
        ),
        threshold_apply=settings.remediation_confidence_threshold_apply,
        threshold_review=settings.remediation_confidence_threshold_review,
        temperature=settings.remediation_confidence_temperature,
    )
    return {
        "score": assessment.score,
        "band": assessment.band,
        "threshold_apply": assessment.threshold_apply,
        "threshold_review": assessment.threshold_review,
        "rationale": assessment.rationale,
    }


def resolve_fix_strategy(
    rule_id: str | None, strategies: dict[str, dict[str, Any]] = AGENTIC_FIX_STRATEGIES
) -> dict[str, Any] | None:
    if not rule_id:
        return None
    capability = get_remediation_capability(rule_id, supported_rule_ids=strategies.keys())
    if not capability.supported:
        return None
    for candidate in rule_id_variants(rule_id):
        strategy = strategies.get(candidate)
        if strategy is not None:
            return strategy
    return None


def preflight_fixability_reason(context: dict[str, Any]) -> str | None:
    rule_id = str(context.get("rule_id") or "")
    source_code = resolve_context_source_code(context)
    return preflight_unsupported_reason(rule_id, source_code)


def build_remediation_no_fix_response(
    *,
    violation_id: str,
    context: dict[str, Any],
    reason: str,
    attempt_count: int | None = None,
) -> dict[str, Any]:
    return build_no_fix_response(
        violation_id=violation_id,
        context=context,
        reason=reason,
        attempt_count=attempt_count,
    )
