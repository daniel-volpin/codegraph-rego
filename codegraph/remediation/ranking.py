"""
Shadow multi-candidate scoring and ranking framework.

Scores and ranks remediation candidates (e.g. deterministic vs LLM) 
based on normalized CandidateOutcomes using deterministic signals.
"""
from __future__ import annotations

import logging
from typing import Literal

from pydantic import BaseModel, Field

from codegraph.remediation.comparison import CandidateOutcome

LOGGER = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class CandidateScore(BaseModel):
    """Score breakdown for a single candidate."""

    source: Literal["deterministic", "llm"]
    total_score: int
    components: dict[str, int]
    explanation: str


class RankedCandidate(BaseModel):
    """A scored candidate."""

    outcome: CandidateOutcome
    score: CandidateScore


class RankingResult(BaseModel):
    """Per-case ranking result."""

    violation_id: str
    rule_id: str
    candidates: list[RankedCandidate]
    recommended_source: str | None
    reason: str | None


class RankingSummary(BaseModel):
    """Aggregate ranking summary across all compared cases."""

    total_cases: int
    recommended_counts: dict[str, int] = Field(default_factory=dict)
    per_rule: dict[str, dict[str, int]] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Scoring Policy
# ---------------------------------------------------------------------------

def score_candidate(outcome: CandidateOutcome) -> CandidateScore:
    """Implement the deterministic point system for a candidate."""
    total = 0
    components = {}
    explanations = []

    if outcome.error is not None:
        components["error"] = -50
        total -= 50
        explanations.append("Failed with error (-50).")
    elif outcome.refused:
        components["refused"] = 0
        explanations.append("Safely refused (0).")
    elif outcome.produced_edits:
        # Check specifically if policy failed to resolve.
        if outcome.policy_resolved is False:
            components["policy_failed"] = -10
            total -= 10
            explanations.append("Produced edits but failed policy verification (-10).")
        else:
            components["success"] = 100
            total += 100
            explanations.append("Produced edits and passed/assumed policy verify (+100).")

    if outcome.edit_count > 0:
        penalty = -outcome.edit_count
        components["minimality_penalty"] = penalty
        total += penalty
        explanations.append(f"Diff footprint penalty ({penalty}).")

    if not explanations:
        explanations.append("No edits, no refusal, no error (0).")

    return CandidateScore(
        source=outcome.source,
        total_score=total,
        components=components,
        explanation=" ".join(explanations),
    )


# ---------------------------------------------------------------------------
# Ranking Logic
# ---------------------------------------------------------------------------

def rank_candidates(
    violation_id: str,
    rule_id: str,
    candidates: list[CandidateOutcome],
) -> RankingResult:
    """Score and sort candidates by total score descending."""
    scored = []
    for c in candidates:
        score = score_candidate(c)
        scored.append(RankedCandidate(outcome=c, score=score))

    # Sort descending by primary score.
    # To tiebreak identical scores, we prefer 'deterministic' source explicitly.
    scored.sort(
        key=lambda rc: (
            rc.score.total_score,
            1 if rc.score.source == "deterministic" else 0
        ),
        reverse=True,
    )

    if not scored:
        return RankingResult(
            violation_id=violation_id,
            rule_id=rule_id,
            candidates=[],
            recommended_source=None,
            reason="No candidates provided",
        )

    best = scored[0]
    
    return RankingResult(
        violation_id=violation_id,
        rule_id=rule_id,
        candidates=scored,
        recommended_source=best.score.source,
        reason=f"Highest score ({best.score.total_score}): {best.score.explanation}",
    )


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

def build_ranking_summary(results: list[RankingResult]) -> RankingSummary:
    """Aggregate ranking recommendations."""
    counts = {"deterministic": 0, "llm": 0, "tie_or_none": 0}
    per_rule: dict[str, dict[str, int]] = {}

    for res in results:
        src = res.recommended_source or "tie_or_none"
        if src not in counts:
            counts[src] = 0
        counts[src] += 1

        rule_counts = per_rule.setdefault(res.rule_id, {"deterministic": 0, "llm": 0, "tie_or_none": 0})
        if src not in rule_counts:
            rule_counts[src] = 0
        rule_counts[src] += 1

    return RankingSummary(
        total_cases=len(results),
        recommended_counts=counts,
        per_rule=per_rule,
    )
