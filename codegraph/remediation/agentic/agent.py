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
from codegraph.remediation.agentic.prompts import (
    SYSTEM_PROMPT_TEMPLATE,
)
from codegraph.remediation.agentic.prompts import (
    build_initial_user_prompt as _build_initial_user_prompt,
)
from codegraph.remediation.agentic.prompts import (
    format_taint_path_dossier as _format_taint_path_dossier,
)
from codegraph.remediation.agentic.tools import AGENT_TOOL_DEFINITIONS, AgentToolExecutor
from codegraph.telemetry import get_tracer

LOGGER = logging.getLogger(__name__)
_tracer = get_tracer("codegraph.remediation.agentic")

__all__ = [
    "AgenticRemediationService",
    "SYSTEM_PROMPT_TEMPLATE",
    "_build_initial_user_prompt",
    "_format_taint_path_dossier",
    "_parse_model_response",
]


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
    """Autonomous agentic remediation service with 3-gate verification and telemetry."""

    def __init__(
        self,
        *,
        llm_client: Callable[..., Any] = generate_chat_completion,
        trajectory_bank: Any | None = None,
        system_prompt: str | None = None,
    ) -> None:
        self.llm_client = llm_client
        self.trajectory_bank = trajectory_bank
        self.system_prompt = system_prompt or SYSTEM_PROMPT_TEMPLATE

    def remediate_finding(
        self,
        finding: dict[str, Any],
        *,
        workspace_root: str | Path,
        max_turns: int = 15,
        model: str | None = None,
        system_prompt: str | None = None,
    ) -> AgentRemediationResult:
        rule_id = str(finding.get("violation_id") or finding.get("rule_id") or "")
        method_key = str(finding.get("method_key") or "")
        target_method = str(finding.get("target_method") or method_key)
        effective_model = model or settings.llm_model
        active_system_prompt = system_prompt or self.system_prompt

        with _tracer.start_as_current_span("remediation.agentic") as span:
            span.set_attribute("openinference.span.kind", "AGENT")
            span.set_attribute("agent.name", "CodeGraphRemediationAgent")
            span.set_attribute("gen_ai.system", "codegraph.agentic")
            span.set_attribute("remediation.rule_id", rule_id)
            span.set_attribute("remediation.method_key", method_key)
            span.set_attribute("remediation.target_method", target_method)
            span.set_attribute("remediation.model", effective_model)
            span.set_attribute("remediation.max_turns", max_turns)

            root = Path(workspace_root).resolve()
            with IsolatedWorktreeEnvironment(root, target_method_key=method_key) as env:
                executor = AgentToolExecutor(env, target_rule_id=rule_id)
                turns: list[AgentTurn] = []

                initial_user_msg = _build_initial_user_prompt(
                    finding,
                    trajectory_bank=self.trajectory_bank,
                )
                messages: list[dict[str, Any]] = [
                    {"role": "system", "content": active_system_prompt},
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
                            model=effective_model,
                            max_tokens=settings.llm_max_tokens_remediation,
                        )
                    except Exception as exc:
                        LOGGER.error("LLM client call failed in agent turn: %s", exc)
                        final_status = "ERROR"
                        final_reason = f"LLM generation failed: {exc}"
                        span.set_attribute("remediation.error", str(exc))
                        break

                    content, tool_calls = _parse_model_response(raw_response)
                    current_turn = AgentTurn(role="assistant", content=content, tool_calls=tool_calls)

                    if not tool_calls:
                        LOGGER.info("no_tool_call content=%s", content[:300])
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

                    messages.append(
                        {
                            "role": "assistant",
                            "content": content,
                            "tool_calls": [tc.to_dict() for tc in tool_calls],
                        }
                    )

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
                        last_verification = env.run_full_verification(rule_id)
                        if last_verification.all_passed:
                            final_status = "SUCCESS"
                            final_reason = finish_reason
                            break
                        else:
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
                if modified_files and final_status != "REFUSED":
                    last_verification = env.run_full_verification(rule_id)
                    if last_verification.all_passed:
                        final_status = "SUCCESS"
                        if final_reason == "Exceeded maximum allowed agent turns.":
                            final_reason = "Verified 3-gate remediation successfully applied."
                elif last_verification is None and final_status == "SUCCESS":
                    last_verification = env.run_full_verification(rule_id)

                span.set_attribute("remediation.outcome", final_status)
                span.set_attribute("remediation.turns_count", len(turns))
                span.set_attribute("remediation.modified_files_count", len(modified_files))
                if last_verification is not None:
                    span.set_attribute("remediation.compile_passed", last_verification.compile_passed)
                    span.set_attribute("remediation.tests_passed", last_verification.tests_passed)
                    span.set_attribute("remediation.policy_passed", last_verification.policy_passed)
                    span.set_attribute("remediation.all_passed", last_verification.all_passed)

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
