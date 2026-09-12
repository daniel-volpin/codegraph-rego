"""Multi-turn autonomous remediation agent with iterative self-correction."""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

from codegraph.config import settings
from codegraph.llm.client import generate_chat_completion
from codegraph.llm.schema.tools import ChatCompletionResponse
from codegraph.remediation.agentic.contracts import (
    AgentOutcomeStatus,
    AgentRemediationResult,
    AgentToolCall,
    AgentTurn,
    AgentVerificationStatus,
)
from codegraph.remediation.agentic.environment import IsolatedWorktreeEnvironment
from codegraph.remediation.agentic.tools import AGENT_TOOL_DEFINITIONS, AgentToolExecutor
from codegraph.remediation.contracts import get_fix_strategy

LOGGER = logging.getLogger(__name__)

SYSTEM_PROMPT_TEMPLATE = """You are an expert autonomous security and software engineering agent.
Your objective is to remediate a verified security violation in a Java codebase by refactoring source code.

Rules & Invariants:
1. Make precise, surgical edits to remediate the vulnerability at its root cause without breaking existing functionality.
2. You can read files, edit code across multiple files, and add imports as needed.
3. Every fix MUST satisfy 3 independent gates:
   - Compilation Gate: JDT / javac must compile with 0 errors.
   - Regression Gate: Project test suite must pass 100%.
   - Policy Gate: The targeted OPA security rule must be fully satisfied (0 violations).
4. When you have applied changes, call 'run_verification' to check all 3 gates.
5. If verification reports compiler errors or test failures, read the diagnostics and iteratively fix them.
6. When all 3 gates pass, call 'finish_remediation' with a clear explanation.
7. If the vulnerability fundamentally cannot be safely automated without external policy or human architectural decisions, call 'refuse_remediation'.
"""


def _format_taint_path_dossier(taint_paths: list[dict[str, Any]]) -> str:
    """Format interprocedural call-graph trace for multi-file context grounding."""
    lines = ["\nInterprocedural Taint Propagation Trace (Call Graph):"]
    for idx, tp in enumerate(taint_paths, start=1):
        sink_type = tp.get("sink_type", "unknown")
        hops = tp.get("hops", 1)
        chain = tp.get("chain") or []
        if chain:
            chain_str = " -> ".join(f"`{hop.get('signature') or hop.get('method_key')}`" for hop in chain)
            lines.append(f"  Path {idx} ({sink_type.upper()} sink, {hops} hops): {chain_str}")
        else:
            lines.append(f"  Path {idx} ({sink_type.upper()} sink, {hops} hops)")
    return "\n".join(lines)


def _build_initial_user_prompt(finding: dict[str, Any]) -> str:
    rule_id = str(finding.get("violation_id") or finding.get("rule_id") or "")
    method_key = str(finding.get("method_key") or "")
    target_method = str(finding.get("target_method") or method_key)
    file_path = str(finding.get("file_path") or "")
    reason = str(finding.get("reason") or "Security finding detected")
    code_snippet = str(finding.get("code_snippet") or (finding.get("evidence") or {}).get("source_code") or "")

    prompt_parts = [
        f"Target Security Violation: {rule_id}",
        f"Target Method: {target_method}",
        f"File Path: {file_path}",
        f"Reason: {reason}",
    ]

    if code_snippet:
        prompt_parts.append(f"Code Snippet:\n{code_snippet}")

    strategy = get_fix_strategy(rule_id, agentic=True)
    if strategy:
        prompt_parts.append("\nRecommended Fix Guidance:")
        prompt_parts.append(f"- Objective: {strategy.get('objective', '')}")
        allowed = strategy.get("allowed_transformations") or []
        if allowed:
            prompt_parts.append("- Allowed Transformations:")
            for t in allowed:
                prompt_parts.append(f"  * {t}")
        non_goals = strategy.get("non_goals") or []
        if non_goals:
            prompt_parts.append("- Non-Goals:")
            for ng in non_goals:
                prompt_parts.append(f"  * {ng}")

    taint_paths = finding.get("taint_paths") or (finding.get("evidence") or {}).get("taint_paths") or []
    if taint_paths:
        prompt_parts.append(_format_taint_path_dossier(taint_paths))

    prompt_parts.append("\nPlease inspect the relevant files, design the necessary refactoring, and apply the fix.")
    return "\n".join(prompt_parts)


def _parse_model_response(raw_response: Any) -> tuple[str, list[AgentToolCall]]:
    parsed = ChatCompletionResponse.from_response(raw_response)
    tool_calls = [
        AgentToolCall(
            call_id=tc.id or uuid.uuid4().hex,
            name=tc.name,
            arguments=tc.arguments,
        )
        for tc in parsed.tool_calls
    ]
    return parsed.content, tool_calls


class AgenticRemediationService:
    """Autonomous agentic remediation service."""

    def __init__(self, *, llm_client: Callable[..., Any] = generate_chat_completion) -> None:
        self.llm_client = llm_client

    def remediate_finding(
        self,
        finding: dict[str, Any],
        *,
        workspace_root: str | Path,
        max_turns: int = 8,
        model: str | None = None,
    ) -> AgentRemediationResult:
        rule_id = str(finding.get("violation_id") or finding.get("rule_id") or "")
        method_key = str(finding.get("method_key") or "")
        target_method = str(finding.get("target_method") or method_key)

        root = Path(workspace_root).resolve()
        with IsolatedWorktreeEnvironment(root) as env:
            executor = AgentToolExecutor(env, target_rule_id=rule_id)
            turns: list[AgentTurn] = []

            # Initialize conversation with taint trace and fix guidance
            initial_user_msg = _build_initial_user_prompt(finding)

            messages: list[dict[str, Any]] = [
                {"role": "system", "content": SYSTEM_PROMPT_TEMPLATE},
                {"role": "user", "content": initial_user_msg},
            ]
            turns.append(AgentTurn(role="user", content=initial_user_msg))

            final_status: AgentOutcomeStatus = "MAX_TURNS_EXCEEDED"
            final_reason = "Exceeded maximum allowed agent turns."
            last_verification: AgentVerificationStatus | None = None

            for turn_idx in range(max_turns):
                LOGGER.info("Agentic remediation turn %d/%d for %s", turn_idx + 1, max_turns, rule_id)
                try:
                    raw_response = self.llm_client(
                        messages,
                        tools=AGENT_TOOL_DEFINITIONS,
                        model=model or settings.llm_model,
                    )
                except Exception as exc:
                    LOGGER.error("LLM client call failed in agent turn: %s", exc)
                    final_status = "ERROR"
                    final_reason = f"LLM generation failed: {exc}"
                    break

                content, tool_calls = _parse_model_response(raw_response)
                current_turn = AgentTurn(role="assistant", content=content, tool_calls=tool_calls)

                if not tool_calls:
                    # Model provided text without tool calls; prompt it to take action or conclude
                    messages.append({"role": "assistant", "content": content})
                    followup = "Please execute a tool call (edit_file, add_import, run_verification, or finish_remediation) to proceed."
                    messages.append({"role": "user", "content": followup})
                    turns.append(current_turn)
                    continue

                tool_results = []
                finish_requested = False
                refuse_requested = False
                finish_reason = ""
                refusal_reason = ""

                for tc in tool_calls:
                    res = executor.execute(tc)
                    tool_results.append(res)
                    if tc.name == "finish_remediation":
                        finish_requested = True
                        finish_reason = tc.arguments.get("reason", "Remediation finished.")
                    elif tc.name == "refuse_remediation":
                        refuse_requested = True
                        refusal_reason = tc.arguments.get("reason", "Remediation refused.")

                current_turn.tool_results = tool_results
                turns.append(current_turn)

                # Append assistant message with tool calls
                messages.append(
                    {
                        "role": "assistant",
                        "content": content,
                        "tool_calls": [tc.to_dict() for tc in tool_calls],
                    }
                )

                # Append tool result messages
                for tr in tool_results:
                    messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": tr.call_id,
                            "content": tr.output,
                        }
                    )

                if refuse_requested:
                    final_status = "REFUSED"
                    final_reason = refusal_reason
                    break

                if finish_requested:
                    # Run authoritative final verification
                    last_verification = env.run_full_verification(rule_id)
                    if last_verification.all_passed:
                        final_status = "SUCCESS"
                        final_reason = finish_reason
                        break
                    else:
                        # Feed failure back to agent for self-healing
                        feedback = (
                            "Final verification failed before completion:\n"
                            f"Compile Passed: {last_verification.compile_passed}\n"
                            f"Compiler Output: {last_verification.compile_output}\n"
                            f"Tests Passed: {last_verification.tests_passed}\n"
                            f"Policy Passed: {last_verification.policy_passed}\n"
                            f"Remaining Violations: {last_verification.remaining_violations}\n\n"
                            "Please correct the errors and verify again."
                        )
                        messages.append({"role": "user", "content": feedback})
                        continue

            modified_files = env.get_modified_files()
            diff = env.compute_unified_diff() if modified_files else ""
            if last_verification is None and final_status == "SUCCESS":
                last_verification = env.run_full_verification(rule_id)

            return AgentRemediationResult(
                status=final_status,
                rule_id=rule_id,
                method_key=method_key,
                target_method=target_method,
                workspace_root=str(root),
                modified_files=modified_files,
                diff=diff,
                verification=last_verification,
                turns=turns,
                reason=final_reason,
                iterations=len(turns),
            )
