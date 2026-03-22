from __future__ import annotations

from pydantic import BaseModel

from codegraph.policy.trace import TraceProfile
from codegraph.remediation.comparison import CandidateOutcome
from codegraph.remediation.ranking import RankingResult


class RemediationDossier(BaseModel):
    """Unified case dossier assembling verification, trace, and ranking outputs into one structured artifact."""

    case_id: str
    rule_id: str
    recommended_source: str | None
    ranking_rationale: str | None
    baseline_trace: TraceProfile | None = None
    remediated_trace: TraceProfile | None = None
    deterministic_outcome: CandidateOutcome | None = None
    llm_outcome: CandidateOutcome | None = None


def build_dossier(
    case_id: str,
    rule_id: str,
    det_outcome: CandidateOutcome,
    llm_outcome: CandidateOutcome,
    ranking: RankingResult,
) -> RemediationDossier:
    """Assembles disjoint candidate properties into a strictly normalized artifact structure."""
    baseline_trace = None
    remediated_trace = None

    if llm_outcome and llm_outcome.predicate_trace:
        raw_before = llm_outcome.predicate_trace.get("before_trace_normalized")
        raw_after = llm_outcome.predicate_trace.get("after_trace_normalized")
        baseline_trace = TraceProfile.model_validate(raw_before) if raw_before else None
        remediated_trace = TraceProfile.model_validate(raw_after) if raw_after else None

    return RemediationDossier(
        case_id=case_id,
        rule_id=rule_id,
        recommended_source=ranking.recommended_source,
        ranking_rationale=ranking.reason,
        baseline_trace=baseline_trace,
        remediated_trace=remediated_trace,
        deterministic_outcome=det_outcome,
        llm_outcome=llm_outcome,
    )
