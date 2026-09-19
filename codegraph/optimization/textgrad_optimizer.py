"""TextGrad prompt and tool optimizer for self-improving remediation agents."""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from codegraph.llm.client import generate_chat_completion
from codegraph.optimization.critic import _extract_content, evaluate_textual_gradient
from codegraph.optimization.evaluator import evaluate_trajectory
from codegraph.remediation.agentic.contracts import AgentRemediationResult

LOGGER = logging.getLogger(__name__)

OPTIMIZER_SYSTEM_PROMPT = """You are an expert Prompt Optimizer implementing TextGrad textual backpropagation.
Your objective is to update a System Prompt for an autonomous security remediation agent based on
accumulated textual gradients (failure critiques and diagnostics) from actual test executions.

Maintain the core 3-gate invariants (Compilation, Test Regression, Policy Clearance).
Incorporate the specific feedback to eliminate observed failure modes while keeping the prompt concise,
authoritative, and actionable.

Current Prompt:
{current_prompt}

Accumulated Textual Gradients:
{gradients}

Output the updated, improved system prompt in structured JSON:
{{
  "updated_prompt": "The refined, improved system prompt text",
  "rationale": "Explanation of changes made to address the gradients"
}}
"""


@dataclass
class OptimizationEpochResult:
    epoch: int
    prompt_before: str
    prompt_after: str
    initial_pass_rate: float
    final_pass_rate: float
    gradients_applied: list[str]
    rationale: str


class TextGradPromptOptimizer:
    """Iterative textual gradient prompt optimizer."""

    def __init__(self, *, llm_client: Callable[..., Any] = generate_chat_completion) -> None:
        self.llm_client = llm_client

    def optimize_prompt(
        self,
        current_prompt: str,
        results: list[AgentRemediationResult],
        *,
        model: str | None = None,
    ) -> tuple[str, list[str], str]:
        """Aggregate gradients from failed cases and synthesize an updated prompt."""
        gradients: list[str] = []

        for res in results:
            score = evaluate_trajectory(res)
            if not score.all_passed:
                critique = evaluate_textual_gradient(res, score, llm_client=self.llm_client, model=model)
                grad = critique.get("textual_gradient")
                rule_id = getattr(res, "rule_id", None) or (res.get("violation_id") if isinstance(res, dict) else "") or (res.get("rule_id") if isinstance(res, dict) else "")
                if grad:
                    gradients.append(f"- Finding '{rule_id}': {grad}")

        if not gradients:
            LOGGER.info("No negative gradients detected; current prompt is optimal for this batch.")
            return current_prompt, [], "No changes needed (100% pass rate)."

        gradients_text = "\n".join(gradients)
        prompt = OPTIMIZER_SYSTEM_PROMPT.format(
            current_prompt=current_prompt,
            gradients=gradients_text,
        )

        try:
            raw = self.llm_client(
                messages=[{"role": "user", "content": prompt}],
                model=model,
                temperature=0.3,
                max_tokens=2048,
            )
            content = _extract_content(raw)
            if "```json" in content:
                content = content.split("```json", 1)[1].split("```", 1)[0].strip()
            elif "```" in content:
                content = content.split("```", 1)[1].split("```", 1)[0].strip()
            parsed = json.loads(content)
            updated = parsed.get("updated_prompt", current_prompt)
            rationale = parsed.get("rationale", "Prompt updated via textual gradient backpropagation.")
            return updated, gradients, rationale
        except Exception as exc:
            LOGGER.error("TextGrad prompt update failed: %s", exc)
            return current_prompt, gradients, f"Update failed: {exc}"
