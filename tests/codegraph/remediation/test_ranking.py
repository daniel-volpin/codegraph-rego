from codegraph.remediation.comparison import CandidateOutcome
from codegraph.remediation.ranking import (
    build_ranking_summary,
    rank_candidates,
    score_candidate,
)


def test_score_success_minimal():
    outcome = CandidateOutcome(
        source="deterministic",
        produced_edits=True,
        refused=False,
        error=None,
        edit_count=1,
        policy_resolved=True,
    )
    score = score_candidate(outcome)
    assert score.source == "deterministic"
    assert score.total_score == 99  # 100 - 1
    assert "success" in score.components
    assert score.components["success"] == 100
    assert score.components["minimality_penalty"] == -1


def test_score_success_larger_footprint():
    outcome = CandidateOutcome(
        source="llm",
        produced_edits=True,
        refused=False,
        error=None,
        edit_count=5,
        policy_resolved=True,
    )
    score = score_candidate(outcome)
    assert score.source == "llm"
    assert score.total_score == 95  # 100 - 5


def test_score_policy_failure_penalty():
    outcome = CandidateOutcome(
        source="llm",
        produced_edits=True,
        refused=False,
        error=None,
        edit_count=2,
        compilation_success=True,
        policy_resolved=False,
    )
    score = score_candidate(outcome)
    assert score.total_score == -12  # -10 base, -2 footprint
    assert "policy_failed" in score.components
    assert score.components["policy_failed"] == -10


def test_score_refusal():
    outcome = CandidateOutcome(
        source="llm",
        produced_edits=False,
        refused=True,
        error=None,
        edit_count=0,
    )
    score = score_candidate(outcome)
    assert score.total_score == 0
    assert "refused" in score.components
    assert score.components["refused"] == 0


def test_score_error():
    outcome = CandidateOutcome(
        source="deterministic",
        produced_edits=False,
        refused=False,
        error="compile_error: mismatched types",
        edit_count=0,
    )
    score = score_candidate(outcome)
    assert score.total_score == -50
    assert "error" in score.components
    assert score.components["error"] == -50


def test_candidate_ordering_success_vs_refusal():
    succ = CandidateOutcome(source="deterministic", produced_edits=True, refused=False, edit_count=1, policy_resolved=True)
    ref = CandidateOutcome(source="llm", produced_edits=False, refused=True)

    result = rank_candidates("case1", "rule1", [succ, ref])
    assert result.recommended_source == "deterministic"
    assert result.candidates[0].score.source == "deterministic"
    assert result.candidates[1].score.source == "llm"


def test_candidate_ordering_refusal_vs_failure():
    ref = CandidateOutcome(source="deterministic", produced_edits=False, refused=True)
    fail = CandidateOutcome(source="llm", produced_edits=False, refused=False, error="timeout")

    result = rank_candidates("case2", "rule1", [fail, ref])
    assert result.recommended_source == "deterministic"
    assert result.candidates[0].score.source == "deterministic"
    assert result.candidates[1].score.source == "llm"


def test_candidate_ordering_refusal_vs_policy_failure():
    ref = CandidateOutcome(source="deterministic", produced_edits=False, refused=True)
    pol_fail = CandidateOutcome(
        source="llm",
        produced_edits=True,
        refused=False,
        error=None,
        edit_count=2,
        compilation_success=True,
        policy_resolved=False,
    )
    
    # Refusal (0) beats policy fail (-10 - 2 = -12)
    result = rank_candidates("case_x", "rule1", [ref, pol_fail])
    assert result.recommended_source == "deterministic"
    assert result.candidates[0].score.source == "deterministic"
    assert result.candidates[1].score.source == "llm"


def test_minimality_preference():
    big = CandidateOutcome(source="llm", produced_edits=True, refused=False, edit_count=10, policy_resolved=True)
    small = CandidateOutcome(source="deterministic", produced_edits=True, refused=False, edit_count=2, policy_resolved=True)

    result = rank_candidates("case3", "rule1", [big, small])
    assert result.recommended_source == "deterministic"
    assert result.candidates[0].score.total_score == 98
    assert result.candidates[1].score.total_score == 90


def test_tiebreaker_preference_for_deterministic():
    # Both identical scores.
    c1 = CandidateOutcome(source="llm", produced_edits=True, refused=False, edit_count=2)
    c2 = CandidateOutcome(source="deterministic", produced_edits=True, refused=False, edit_count=2)

    result = rank_candidates("case4", "rule1", [c1, c2])
    assert result.recommended_source == "deterministic"


def test_build_ranking_summary():
    r1 = rank_candidates(
        "case1", "r1",
        [CandidateOutcome(source="deterministic", produced_edits=True, refused=False, edit_count=1),
         CandidateOutcome(source="llm", produced_edits=False, refused=True)],
    )
    r2 = rank_candidates(
        "case2", "r1",
        [CandidateOutcome(source="deterministic", produced_edits=False, refused=False, error="fail"),
         CandidateOutcome(source="llm", produced_edits=True, refused=False, edit_count=3)],
    )
    
    summary = build_ranking_summary([r1, r2])
    assert summary.total_cases == 2
    assert summary.recommended_counts["deterministic"] == 1
    assert summary.recommended_counts["llm"] == 1
    assert summary.per_rule["r1"]["deterministic"] == 1
    assert summary.per_rule["r1"]["llm"] == 1


def test_config_flag_default_behavior():
    from codegraph.config import Settings
    settings = Settings(_env_file=None)
    assert settings.remediation_ranking_enabled is False
    assert settings.remediation_ranking_mode == "off"


def test_artifact_serialization():
    outcome = CandidateOutcome(source="llm", produced_edits=True, refused=False, edit_count=1)
    result = rank_candidates("v1", "r1", [outcome])
    dump = result.model_dump()
    assert dump["violation_id"] == "v1"
    assert dump["recommended_source"] == "llm"
    assert "candidates" in dump
