"""3-Gate verification objective evaluator and trajectory scoring engine."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from codegraph.remediation.agentic.contracts import AgentVerificationStatus


@dataclass(frozen=True)
class TrajectoryEvaluationScore:
    """Quantitative score for an agent remediation trajectory."""

    total_score: float
    compile_score: float
    test_score: float
    policy_score: float
    efficiency_penalty: float
    all_passed: bool
    iterations: int
    tool_call_count: int
    no_tool_call_count: int
    diagnostics: list[str]


def evaluate_trajectory(
    result: Any,
    *,
    weight_compile: float = 0.3,
    weight_tests: float = 0.3,
    weight_policy: float = 0.4,
    turn_penalty_rate: float = 0.02,
) -> TrajectoryEvaluationScore:
    """Evaluate a remediation run's quality, gate satisfaction, and turn efficiency."""
    verification = getattr(result, "verification", None) or (result.get("verification") if isinstance(result, dict) else None)
    status = getattr(result, "status", None) or (result.get("status") if isinstance(result, dict) else "")

    if isinstance(verification, dict):
        compile_passed = bool(verification.get("compile_passed"))
        tests_passed = bool(verification.get("tests_passed"))
        policy_passed = bool(verification.get("policy_passed"))
        all_passed = bool(status == "SUCCESS" and verification.get("all_passed"))
        compile_output = verification.get("compile_output")
        test_output = verification.get("test_output")
        remaining_violations = verification.get("remaining_violations") or []
    elif isinstance(verification, AgentVerificationStatus):
        compile_passed = bool(verification.compile_passed)
        tests_passed = bool(verification.tests_passed)
        policy_passed = bool(verification.policy_passed)
        all_passed = bool(status == "SUCCESS" and verification.all_passed)
        compile_output = verification.compile_output
        test_output = verification.test_output
        remaining_violations = verification.remaining_violations or []
    else:
        compile_passed = False
        tests_passed = False
        policy_passed = False
        all_passed = False
        compile_output = None
        test_output = None
        remaining_violations = []

    compile_score = weight_compile if compile_passed else 0.0
    test_score = weight_tests if tests_passed else 0.0
    policy_score = weight_policy if policy_passed else 0.0

    tool_call_count = 0
    no_tool_call_count = 0
    diagnostics: list[str] = []

    if compile_output and not compile_passed:
        diagnostics.append(f"Compiler Error: {compile_output}")
    if test_output and not tests_passed:
        diagnostics.append(f"Test Regression: {test_output}")
    if remaining_violations and not policy_passed:
        diagnostics.append(f"Remaining Policy Violations: {', '.join(remaining_violations)}")

    raw_turns = getattr(result, "turns", None) or (result.get("transcript") if isinstance(result, dict) else None) or (result.get("turns") if isinstance(result, dict) else [])
    turns = raw_turns if raw_turns is not None else []
    for turn in turns:
        role = getattr(turn, "role", None) or (turn.get("role") if isinstance(turn, dict) else None)
        if role == "assistant":
            calls = getattr(turn, "tool_calls", None) or (turn.get("tool_calls") if isinstance(turn, dict) else [])
            if calls:
                tool_call_count += len(calls)
            else:
                no_tool_call_count += 1

    iterations = max(1, len(turns))
    efficiency_penalty = (iterations * turn_penalty_rate) + (no_tool_call_count * 0.05)
    total_score = max(0.0, (compile_score + test_score + policy_score) - efficiency_penalty)

    return TrajectoryEvaluationScore(
        total_score=round(total_score, 4),
        compile_score=compile_score,
        test_score=test_score,
        policy_score=policy_score,
        efficiency_penalty=round(efficiency_penalty, 4),
        all_passed=all_passed,
        iterations=iterations,
        tool_call_count=tool_call_count,
        no_tool_call_count=no_tool_call_count,
        diagnostics=diagnostics,
    )
    efficiency_penalty = (iterations * turn_penalty_rate) + (no_tool_call_count * 0.05)
    total_score = max(0.0, (compile_score + test_score + policy_score) - efficiency_penalty)

    return TrajectoryEvaluationScore(
        total_score=round(total_score, 4),
        compile_score=compile_score,
        test_score=test_score,
        policy_score=policy_score,
        efficiency_penalty=round(efficiency_penalty, 4),
        all_passed=all_passed,
        iterations=iterations,
        tool_call_count=tool_call_count,
        no_tool_call_count=no_tool_call_count,
        diagnostics=diagnostics,
    )
