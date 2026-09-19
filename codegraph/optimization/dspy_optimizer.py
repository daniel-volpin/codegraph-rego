"""DSPy-compatible declarative modules and teleprompter optimization wrapper."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class RemediationTrajectoryDemonstration:
    """A grounded, verified few-shot trajectory demonstration for DSPy bootstrapping."""

    rule_id: str
    target_method: str
    initial_code: str
    tool_sequence: list[str]
    final_patch: str
    verification_summary: str


class RemediationSignature:
    """Declarative signature for autonomous security repair."""

    name = "RemediateVulnerability"
    docstring = "Remediate a Java security vulnerability while strictly satisfying compilation, test, and policy gates."
    inputs = ["code_snippet", "rule_id", "taint_trace", "control_summary"]
    outputs = ["reasoning", "action_plan", "remediated_code"]


class DSPyPromptCompiler:
    """Compiles and formats DSPy declarative signatures and optimized few-shot demonstrations."""

    def __init__(self, demonstrations: list[RemediationTrajectoryDemonstration] | None = None) -> None:
        self.demonstrations = demonstrations or []

    def add_demonstration(self, demo: RemediationTrajectoryDemonstration) -> None:
        self.demonstrations.append(demo)

    def compile_instruction_prompt(self, base_instructions: str) -> str:
        """Compile base instructions enriched with high-signal bootstrapped few-shot examples."""
        if not self.demonstrations:
            return base_instructions

        lines = [base_instructions, "\n### Verified Reference Demonstrations (Few-Shot):"]
        for idx, demo in enumerate(self.demonstrations, 1):
            lines.append(f"\n--- Example {idx}: {demo.rule_id} ---")
            lines.append(f"Target Method: {demo.target_method}")
            lines.append(f"Initial Code:\n```java\n{demo.initial_code}\n```")
            lines.append(f"Verified Patch:\n```java\n{demo.final_patch}\n```")
            lines.append(f"Verification: {demo.verification_summary}")

        return "\n".join(lines)


def bootstrap_few_shot_demos_from_results(
    results: list[Any], max_demos_per_rule: int = 1
) -> list[RemediationTrajectoryDemonstration]:
    """Extract clean, successful trajectories from evaluation results to serve as few-shot demos."""
    demos: list[RemediationTrajectoryDemonstration] = []
    seen_rules: dict[str, int] = {}

    for res in results:
        status = getattr(res, "status", None) or (res.get("status") if isinstance(res, dict) else None)
        if status != "SUCCESS":
            continue

        rule_id = str(getattr(res, "rule_id", None) or (res.get("rule_id") if isinstance(res, dict) else "") or "")
        if seen_rules.get(rule_id, 0) >= max_demos_per_rule:
            continue

        diff = str(getattr(res, "diff", None) or (res.get("diff") if isinstance(res, dict) else "") or "")
        method = str(getattr(res, "target_method", None) or (res.get("target_method") if isinstance(res, dict) else "") or "")

        tool_seq = []
        raw_turns = (
            getattr(res, "turns", None)
            or (res.get("transcript") if isinstance(res, dict) else None)
            or (res.get("turns") if isinstance(res, dict) else [])
        )
        turns = raw_turns if raw_turns is not None else []
        for t in turns:
            calls = getattr(t, "tool_calls", None) or (t.get("tool_calls") if isinstance(t, dict) else [])
            for c in calls:
                name = getattr(c, "name", None) or (c.get("name") if isinstance(c, dict) else "")
                if name:
                    tool_seq.append(name)

        demos.append(
            RemediationTrajectoryDemonstration(
                rule_id=rule_id,
                target_method=method,
                initial_code="(vulnerable source)",
                tool_sequence=tool_seq,
                final_patch=diff,
                verification_summary="Passed Compilation, Tests, and Policy Gates (100%).",
            )
        )
        seen_rules[rule_id] = seen_rules.get(rule_id, 0) + 1

    return demos
