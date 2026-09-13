"""
Shadow comparison of deterministic vs LLM remediation outcomes.

This module provides structured models and pure functions for comparing
the deterministic compiler-based remediation path against the existing
LLM generation path on the same violation case.  All logic is evaluation-
only and does not alter the live remediation flow.
"""

from __future__ import annotations

import difflib
import logging
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field

from codegraph.remediation.patch_compiler import CompileError, compile_repair_intent
from codegraph.remediation.repair_intent import (
    RepairIntentKind,
    plan_repair_intent,
)

LOGGER = logging.getLogger(__name__)




class ComparisonLabel(StrEnum):
    """Outcome-oriented classification of a deterministic-vs-LLM comparison."""

    BOTH_PRODUCED_EDITS = "both_produced_edits"
    DETERMINISTIC_ONLY = "deterministic_only"
    LLM_ONLY = "llm_only"
    BOTH_REFUSED = "both_refused"
    BOTH_FAILED = "both_failed"
    DETERMINISTIC_REFUSED_LLM_PRODUCED = "deterministic_refused_llm_produced"
    LLM_REFUSED_DETERMINISTIC_PRODUCED = "llm_refused_deterministic_produced"




class CandidateOutcome(BaseModel):
    """Normalized result from a single remediation path."""

    source: Literal["deterministic", "llm"]
    produced_edits: bool
    refused: bool
    error: str | None = None
    edit_count: int = 0
    diff_snippet: str | None = None
    compilation_success: bool | None = None
    policy_resolved: bool | None = None
    predicate_trace: dict[str, Any] | None = None


class ComparisonResult(BaseModel):
    """Per-case comparison of deterministic vs LLM remediation."""

    violation_id: str
    rule_id: str
    file_path: str
    target_method: str
    label: ComparisonLabel
    deterministic: CandidateOutcome
    llm: CandidateOutcome


class ComparisonSummary(BaseModel):
    """Aggregate summary across all compared cases."""

    total_cases: int
    label_counts: dict[str, int] = Field(default_factory=dict)
    per_rule: dict[str, dict[str, int]] = Field(default_factory=dict)




def classify_comparison(
    det: CandidateOutcome,
    llm: CandidateOutcome,
) -> ComparisonLabel:
    """Classify the outcome pair into an outcome-oriented label."""
    if det.produced_edits and llm.produced_edits:
        return ComparisonLabel.BOTH_PRODUCED_EDITS
    if det.produced_edits and not llm.produced_edits:
        if llm.refused:
            return ComparisonLabel.LLM_REFUSED_DETERMINISTIC_PRODUCED
        return ComparisonLabel.DETERMINISTIC_ONLY
    if llm.produced_edits and not det.produced_edits:
        if det.refused:
            return ComparisonLabel.DETERMINISTIC_REFUSED_LLM_PRODUCED
        return ComparisonLabel.LLM_ONLY
    # Neither produced edits.
    if det.refused and llm.refused:
        return ComparisonLabel.BOTH_REFUSED
    return ComparisonLabel.BOTH_FAILED




def build_deterministic_outcome(
    context: dict[str, Any],
    source_lines: list[str],
) -> CandidateOutcome:
    """Run the deterministic planner + compiler and normalise the result.

    This catches :class:`CompileError` and planner refusals, recording
    them in the outcome rather than propagating exceptions.
    """
    try:
        intent = plan_repair_intent(context)
    except Exception as exc:
        LOGGER.debug("Deterministic planner error: %s", exc)
        return CandidateOutcome(
            source="deterministic",
            produced_edits=False,
            refused=False,
            error=f"planner_error: {exc}",
        )

    if intent.kind == RepairIntentKind.NO_REPAIR:
        return CandidateOutcome(
            source="deterministic",
            produced_edits=False,
            refused=True,
            error=intent.refusal.explanation if intent.refusal else "no_repair",
        )

    try:
        edits = compile_repair_intent(intent, source_lines)
    except CompileError as exc:
        LOGGER.debug("Deterministic compiler error: %s", exc)
        return CandidateOutcome(
            source="deterministic",
            produced_edits=False,
            refused=False,
            error=f"compile_error: {exc}",
        )

    if not edits:
        return CandidateOutcome(
            source="deterministic",
            produced_edits=False,
            refused=False,
            error="empty_edits",
        )

    diff = _edits_to_diff_snippet(edits)
    return CandidateOutcome(
        source="deterministic",
        produced_edits=True,
        refused=False,
        edit_count=len(edits),
        diff_snippet=diff,
        compilation_success=True,  # deterministic guarantees syntax parse
        policy_resolved=None,  # typically verified downstream, but we distinguish it
    )


def build_llm_outcome(apply_result: dict[str, Any]) -> CandidateOutcome:
    """Normalise an existing LLM apply-flow result dict into a CandidateOutcome."""
    status = str(apply_result.get("status") or "")
    error = apply_result.get("error")
    diff = apply_result.get("diff")
    generation = apply_result.get("generation") or {}

    edits = generation.get("edits") or []
    decision = str(generation.get("decision") or "").lower()

    produced_edits = bool(apply_result.get("updated_source_code"))
    refused = status == "NO_FIX" or decision == "no_fix"

    comp_success = None
    if "compilation" in apply_result:
        comp_success = apply_result["compilation"].get("success")

    pol_resolved = None
    verification = apply_result.get("verification") or {}
    if verification:
        pol_resolved = verification.get("target_rule_status") == "PASS"

    pred_trace = apply_result.get("predicate_trace")

    return CandidateOutcome(
        source="llm",
        produced_edits=produced_edits,
        refused=refused,
        error=str(error) if error else None,
        edit_count=len(edits) if isinstance(edits, list) else 0,
        diff_snippet=str(diff) if diff else None,
        compilation_success=comp_success,
        policy_resolved=pol_resolved,
        predicate_trace=pred_trace,
    )




def compare_remediation(
    violation_context: dict[str, Any],
    det_outcome: CandidateOutcome,
    llm_outcome: CandidateOutcome,
) -> ComparisonResult:
    """Build a structured comparison result for one violation case."""
    label = classify_comparison(det_outcome, llm_outcome)
    return ComparisonResult(
        violation_id=str(violation_context.get("violation_id") or "unknown"),
        rule_id=str(violation_context.get("rule_id") or "unknown"),
        file_path=str(violation_context.get("file_path") or "unknown"),
        target_method=str(violation_context.get("target_method") or "unknown"),
        label=label,
        deterministic=det_outcome,
        llm=llm_outcome,
    )




def build_comparison_summary(
    results: list[ComparisonResult],
) -> ComparisonSummary:
    """Aggregate comparison results into a summary with per-rule breakdowns."""
    label_counts: dict[str, int] = {label.value: 0 for label in ComparisonLabel}
    per_rule: dict[str, dict[str, int]] = {}

    for result in results:
        label_counts[result.label.value] = label_counts.get(result.label.value, 0) + 1

        rule_counts = per_rule.setdefault(
            result.rule_id,
            {label.value: 0 for label in ComparisonLabel},
        )
        rule_counts[result.label.value] = rule_counts.get(result.label.value, 0) + 1

    return ComparisonSummary(
        total_cases=len(results),
        label_counts=label_counts,
        per_rule=per_rule,
    )


def render_comparison_summary_markdown(summary: ComparisonSummary) -> str:
    """Render a human-readable markdown summary."""
    lines = [
        "# Remediation Comparison Summary",
        "",
        f"**Total cases:** {summary.total_cases}",
        "",
        "## Outcome Distribution",
        "",
        "| Label | Count |",
        "| --- | --- |",
    ]
    for label, count in sorted(summary.label_counts.items()):
        lines.append(f"| `{label}` | {count} |")

    if summary.per_rule:
        lines.extend(["", "## Per-Rule Breakdown"])
        for rule_id in sorted(summary.per_rule):
            rule_counts = summary.per_rule[rule_id]
            non_zero = {k: v for k, v in rule_counts.items() if v > 0}
            if not non_zero:
                continue
            lines.extend(["", f"### `{rule_id}`", ""])
            for label, count in sorted(non_zero.items()):
                lines.append(f"- `{label}`: {count}")

    lines.append("")
    return "\n".join(lines)




def _edits_to_diff_snippet(edits: list[dict[str, Any]]) -> str:
    """Convert edit dicts to a unified-diff-style snippet."""
    fragments: list[str] = []
    for edit in edits:
        original = edit.get("original_lines") or []
        replacement = edit.get("replacement_lines") or []
        diff = difflib.unified_diff(
            original,
            replacement,
            fromfile="before",
            tofile="after",
            lineterm="",
        )
        fragments.extend(diff)
    return "\n".join(fragments) if fragments else ""
