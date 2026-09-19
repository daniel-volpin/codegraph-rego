"""Prompt and tool optimization package: TextGrad backpropagation and DSPy programmatic prompt tuning."""

from __future__ import annotations

from codegraph.optimization.critic import evaluate_textual_gradient
from codegraph.optimization.dspy_optimizer import (
    DSPyPromptCompiler,
    RemediationSignature,
    bootstrap_few_shot_demos_from_results,
)
from codegraph.optimization.evaluator import TrajectoryEvaluationScore, evaluate_trajectory
from codegraph.optimization.evolution_loop import ContinuousEvolutionEngine, EvolutionEpochReport
from codegraph.optimization.textgrad_optimizer import OptimizationEpochResult, TextGradPromptOptimizer
from codegraph.optimization.trajectory_bank import TrajectoryBank, TrajectoryBankEntry

__all__ = [
    "ContinuousEvolutionEngine",
    "DSPyPromptCompiler",
    "EvolutionEpochReport",
    "OptimizationEpochResult",
    "RemediationSignature",
    "TextGradPromptOptimizer",
    "TrajectoryBank",
    "TrajectoryBankEntry",
    "TrajectoryEvaluationScore",
    "bootstrap_few_shot_demos_from_results",
    "evaluate_textual_gradient",
    "evaluate_trajectory",
]
