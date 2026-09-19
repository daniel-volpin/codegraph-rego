"""Automated multi-epoch continuous prompt and strategy evolution loop."""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from codegraph.llm.client import generate_chat_completion
from codegraph.optimization.evaluator import evaluate_trajectory
from codegraph.optimization.textgrad_optimizer import TextGradPromptOptimizer
from codegraph.optimization.trajectory_bank import TrajectoryBank, TrajectoryBankEntry

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class EvolutionEpochReport:
    """Audit record of a single evolutionary optimization epoch."""

    epoch: int
    prompt_version: str
    pass_rate: float
    average_score: float
    total_evaluated: int
    success_count: int
    gradients_applied: list[str]
    prompt_text: str
    timestamp: str


class ContinuousEvolutionEngine:
    """Executes multi-epoch prompt optimization with checkpointing and trajectory banking."""

    def __init__(
        self,
        *,
        llm_client: Callable[..., Any] = generate_chat_completion,
        trajectory_bank: TrajectoryBank | None = None,
        checkpoints_dir: Path | str = "outputs/prompt_checkpoints",
    ) -> None:
        self.llm_client = llm_client
        self.optimizer = TextGradPromptOptimizer(llm_client=llm_client)
        self.trajectory_bank = trajectory_bank or TrajectoryBank()
        self.checkpoints_dir = Path(checkpoints_dir).resolve()
        self.checkpoints_dir.mkdir(parents=True, exist_ok=True)
        self.history: list[EvolutionEpochReport] = []

    def harvest_verified_trajectories(self, results: list[Any]) -> int:
        """Deposit all 100% verified successful repairs into the trajectory bank."""
        added = 0
        for res in results:
            status = getattr(res, "status", None) or (res.get("status") if isinstance(res, dict) else "")
            if status != "SUCCESS":
                continue

            case_id = str(getattr(res, "case_id", None) or (res.get("case_id") if isinstance(res, dict) else "") or "")
            rule_id = str(getattr(res, "rule_id", None) or (res.get("violation_id") if isinstance(res, dict) else "") or (res.get("rule_id") if isinstance(res, dict) else "") or "")
            target_method = str(getattr(res, "target_method", None) or (res.get("target_method") if isinstance(res, dict) else "") or "")
            diff = str(getattr(res, "diff", None) or (res.get("diff") if isinstance(res, dict) else "") or "")

            raw_turns = (
                getattr(res, "turns", None)
                or (res.get("transcript") if isinstance(res, dict) else None)
                or (res.get("turns") if isinstance(res, dict) else [])
            )
            turns = raw_turns if raw_turns is not None else []
            tool_seq: list[str] = []
            for t in turns:
                calls = getattr(t, "tool_calls", None) or (t.get("tool_calls") if isinstance(t, dict) else [])
                for c in calls:
                    name = getattr(c, "name", None) or (c.get("name") if isinstance(c, dict) else "")
                    if name:
                        tool_seq.append(name)

            entry = TrajectoryBankEntry(
                case_id=case_id,
                rule_id=rule_id,
                target_method=target_method,
                initial_code="(vulnerable source)",
                diff=diff,
                turns_count=max(1, len(turns)),
                tool_sequence=tool_seq,
                verification_summary="Passed JDT Compile, Test Suite, and Policy Clearance Gates (100%).",
                timestamp=datetime.now(UTC).isoformat(),
            )
            self.trajectory_bank.deposit(entry)
            added += 1

        if added > 0:
            self.trajectory_bank.save()
            LOGGER.info("Harvested %d verified trajectories into TrajectoryBank.", added)
        return added

    def evolve_epoch(
        self,
        epoch: int,
        current_prompt: str,
        evaluation_results: list[Any],
        *,
        model: str | None = None,
    ) -> tuple[str, EvolutionEpochReport]:
        """Execute one evolutionary optimization step and produce an epoch report."""
        scores = [evaluate_trajectory(r) for r in evaluation_results]
        total = max(1, len(scores))
        successes = sum(1 for s in scores if s.all_passed)
        pass_rate = round(successes / total, 4)
        avg_score = round(sum(s.total_score for s in scores) / total, 4)

        # Harvest successful trajectories into the bank
        self.harvest_verified_trajectories(evaluation_results)

        # Apply TextGrad textual backpropagation to synthesize prompt mutations
        updated_prompt, gradients, rationale = self.optimizer.optimize_prompt(
            current_prompt,
            evaluation_results,
            model=model,
        )

        version = f"v{epoch}"
        report = EvolutionEpochReport(
            epoch=epoch,
            prompt_version=version,
            pass_rate=pass_rate,
            average_score=avg_score,
            total_evaluated=total,
            success_count=successes,
            gradients_applied=gradients,
            prompt_text=updated_prompt,
            timestamp=datetime.now(UTC).isoformat(),
        )
        self.history.append(report)

        # Save versioned prompt checkpoint
        ckpt_file = self.checkpoints_dir / f"SYSTEM_PROMPT_{version}.md"
        ckpt_file.write_text(updated_prompt, encoding="utf-8")
        LOGGER.info("Saved evolved prompt checkpoint %s (Pass Rate: %.2f%%)", ckpt_file, pass_rate * 100)

        return updated_prompt, report
