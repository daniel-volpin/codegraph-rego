from codegraph.remediation.dossier import build_dossier
from codegraph.remediation.comparison import CandidateOutcome
from codegraph.remediation.ranking import RankingResult, RankedCandidate, score_candidate
from codegraph.policy.trace import TraceProfile


def test_build_dossier_extracts_trace_from_llm_outcome():
    # Setup dummy outcomes
    det_outcome = CandidateOutcome(
        source="deterministic",
        produced_edits=True,
        refused=False,
        error=None,
        edit_count=1,
    )

    before_trace = TraceProfile(
        rule_id="CWE-328",
        is_vulnerable=True,
        detected_via_source=True,
        detected_via_graph=False,
        detected_via_ast=False,
    )
    after_trace = TraceProfile(
        rule_id="CWE-328",
        is_vulnerable=False,
        detected_via_source=False,
        detected_via_graph=False,
        detected_via_ast=False,
    )

    llm_outcome = CandidateOutcome(
        source="llm",
        produced_edits=True,
        refused=False,
        error=None,
        edit_count=1,
        predicate_trace={
            "before_trace_normalized": before_trace.model_dump(),
            "after_trace_normalized": after_trace.model_dump(),
        },
    )

    ranking = RankingResult(
        violation_id="v1",
        rule_id="CWE-328",
        recommended_source="llm",
        reason="LLM patch passed verification cleanly.",
        candidate_scores={"llm": 100, "deterministic": 0},
        candidates=[
            RankedCandidate(outcome=det_outcome, score=score_candidate(det_outcome)),
            RankedCandidate(outcome=llm_outcome, score=score_candidate(llm_outcome)),
        ],
    )

    dossier = build_dossier(
        case_id="case-001", rule_id="CWE-328", det_outcome=det_outcome, llm_outcome=llm_outcome, ranking=ranking
    )

    assert dossier.case_id == "case-001"
    assert dossier.rule_id == "CWE-328"
    assert dossier.recommended_source == "llm"
    assert dossier.ranking_rationale == "LLM patch passed verification cleanly."
    assert dossier.baseline_trace is not None
    assert dossier.baseline_trace.is_vulnerable is True
    assert dossier.remediated_trace is not None
    assert dossier.remediated_trace.is_vulnerable is False
    assert dossier.deterministic_outcome == det_outcome
    assert dossier.llm_outcome == llm_outcome


def test_build_dossier_handles_missing_traces_safely():
    # Setup missing inputs
    det_outcome = CandidateOutcome(source="deterministic", produced_edits=False, refused=True, error=None, edit_count=0)
    llm_outcome = CandidateOutcome(
        source="llm", produced_edits=False, refused=True, error=None, edit_count=0, predicate_trace=None
    )
    ranking = RankingResult(
        violation_id="v2",
        rule_id="unknown_rule",
        recommended_source="deterministic",
        reason="both refused, det wins tiebreaker.",
        candidate_scores={"llm": 0, "deterministic": 0},
        candidates=[
            RankedCandidate(outcome=det_outcome, score=score_candidate(det_outcome)),
            RankedCandidate(outcome=llm_outcome, score=score_candidate(llm_outcome)),
        ],
    )

    dossier = build_dossier(
        case_id="case-002", rule_id="unknown_rule", det_outcome=det_outcome, llm_outcome=llm_outcome, ranking=ranking
    )

    assert dossier.case_id == "case-002"
    assert dossier.baseline_trace is None
    assert dossier.remediated_trace is None
    assert dossier.recommended_source == "deterministic"
