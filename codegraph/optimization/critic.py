"""Textual loss critic that computes natural-language gradients from failed trajectories."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from codegraph.llm.client import generate_chat_completion
from codegraph.optimization.evaluator import TrajectoryEvaluationScore

CRITIC_PROMPT_TEMPLATE = """You are an expert AI Prompt and Autonomous Agent Critic.
Your objective is to analyze a failed remediation trajectory from a software security agent
and compute a precise "Textual Gradient" (constructive natural-language feedback) to improve
the system instructions, tool descriptions, and action protocols.

Target Violation: {rule_id}
Status: {status}
Failure Diagnostics:
{diagnostics}

Agent Transcript Summary:
{transcript}

Analyze why the agent failed or diverged:
1. Did the agent write custom runtime escaping rather than parameterizing/sanitizing at the sink?
2. Did the agent produce compiler errors (syntax/scoping)?
3. Did the agent waste turns thinking without calling tools?

Generalization Rule (Zero Overfitting):
- Formulate the textual gradient as a general principle of sound Java security design and tool protocol.
- Do NOT include benchmark-specific class names (e.g. BenchmarkTest*, DatabaseHelper), filenames, or case IDs in the gradient.

Output your critique in structured JSON:
{{
  "root_failure_mode": "string",
  "textual_gradient": "Actionable, precise guidance instruction to add or refine in the system prompt",
  "tool_docstring_improvement": "Suggested refinement to tool parameter descriptions if applicable, or null"
}}
"""


def format_transcript_summary(result: Any, max_turns: int = 5) -> str:
    """Extract a concise readable summary of the agent trajectory."""
    lines: list[str] = []
    raw_turns = (
        getattr(result, "turns", None)
        or (result.get("transcript") if isinstance(result, dict) else None)
        or (result.get("turns") if isinstance(result, dict) else [])
    )
    turns = raw_turns if raw_turns is not None else []
    for idx, turn in enumerate(turns[:max_turns], 1):
        role = getattr(turn, "role", None) or (turn.get("role") if isinstance(turn, dict) else None)
        if role == "assistant":
            calls = getattr(turn, "tool_calls", None) or (turn.get("tool_calls") if isinstance(turn, dict) else [])
            call_names = []
            for tc in calls:
                name = getattr(tc, "name", None) or (tc.get("name") if isinstance(tc, dict) else "")
                args = getattr(tc, "arguments", None) or (tc.get("arguments") if isinstance(tc, dict) else {})
                call_names.append(f"{name}({list(args.keys()) if isinstance(args, dict) else ''})")
            lines.append(f"Turn {idx} [Assistant]: calls={call_names}")
            tool_results = getattr(turn, "tool_results", None) or (turn.get("tool_results") if isinstance(turn, dict) else [])
            for tr in tool_results:
                name = getattr(tr, "name", None) or (tr.get("name") if isinstance(tr, dict) else "")
                output = getattr(tr, "output", None) or (tr.get("output") if isinstance(tr, dict) else "")
                lines.append(f"  Result {name}: {str(output)[:150]}")
        elif role == "user" and idx > 1:
            content = getattr(turn, "content", None) or (turn.get("content") if isinstance(turn, dict) else "")
            lines.append(f"Turn {idx} [User/Feedback]: {str(content)[:150]}")
    return "\n".join(lines)


def _extract_content(raw: Any) -> str:
    if isinstance(raw, str):
        return raw
    choices = getattr(raw, "choices", None) or (raw.get("choices") if isinstance(raw, dict) else None) or []
    if choices:
        first = choices[0]
        msg = getattr(first, "message", None) or (first.get("message") if isinstance(first, dict) else None)
        if msg:
            content = getattr(msg, "content", None) or (msg.get("content") if isinstance(msg, dict) else None)
            if isinstance(content, str):
                return content
    return str(raw or "{}")


def evaluate_textual_gradient(
    result: Any,
    score: TrajectoryEvaluationScore,
    *,
    llm_client: Callable[..., Any] = generate_chat_completion,
    model: str | None = None,
) -> dict[str, str | None]:
    """Compute natural language feedback gradients from verification failure diagnostics."""
    if score.all_passed:
        return {
            "root_failure_mode": "none",
            "textual_gradient": None,
            "tool_docstring_improvement": None,
        }

    diagnostics_text = "\n".join(f"- {d}" for d in score.diagnostics) or "- No explicit gate diagnostics provided"
    transcript_text = format_transcript_summary(result)
    rule_id = getattr(result, "rule_id", None) or (result.get("violation_id") if isinstance(result, dict) else "") or (result.get("rule_id") if isinstance(result, dict) else "")
    status = getattr(result, "status", None) or (result.get("status") if isinstance(result, dict) else "")

    prompt = CRITIC_PROMPT_TEMPLATE.format(
        rule_id=rule_id,
        status=status,
        diagnostics=diagnostics_text,
        transcript=transcript_text,
    )

    try:
        raw = llm_client(
            messages=[{"role": "user", "content": prompt}],
            model=model,
            temperature=0.2,
            max_tokens=2048,
        )
        content = _extract_content(raw)
        if "```json" in content:
            content = content.split("```json", 1)[1].split("```", 1)[0].strip()
        elif "```" in content:
            content = content.split("```", 1)[1].split("```", 1)[0].strip()
        return json.loads(content)
    except Exception:
        return {
            "root_failure_mode": "evaluation_error",
            "textual_gradient": f"Ensure all 3 gates pass and avoid: {diagnostics_text}",
            "tool_docstring_improvement": None,
        }
