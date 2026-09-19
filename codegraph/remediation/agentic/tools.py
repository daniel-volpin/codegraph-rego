"""Tools available to the autonomous remediation agent."""

from __future__ import annotations

import json
import logging
from typing import Any

from codegraph.remediation.agentic.contracts import AgentToolCall, AgentToolResult
from codegraph.remediation.agentic.environment import IsolatedWorktreeEnvironment
from codegraph.remediation.agentic.tool_schemas import AGENT_TOOL_DEFINITIONS

LOGGER = logging.getLogger(__name__)

__all__ = ["AGENT_TOOL_DEFINITIONS", "AgentToolExecutor"]


class AgentToolExecutor:
    """Executes tool calls against the sandboxed environment."""

    def __init__(self, env: IsolatedWorktreeEnvironment, target_rule_id: str) -> None:
        self.env = env
        self.target_rule_id = target_rule_id

    def execute(self, tool_call: AgentToolCall) -> AgentToolResult:
        name = tool_call.name
        args = tool_call.arguments
        LOGGER.info("tool_call name=%s args=%s", name, json.dumps(args)[:200])
        try:
            if name == "read_file":
                rel = args.get("relative_path", "")
                content = self.env.read_file(rel)
                return AgentToolResult(call_id=tool_call.call_id, name=name, output=content, success=True)

            elif name == "find_files":
                pattern = args.get("pattern", "**/*")
                files = self.env.find_files(pattern)
                return AgentToolResult(
                    call_id=tool_call.call_id,
                    name=name,
                    output=json.dumps(files, indent=2),
                    success=True,
                )

            elif name == "search_code":
                pattern = args.get("pattern", "")
                results = self.env.search_code(pattern)
                return AgentToolResult(
                    call_id=tool_call.call_id,
                    name=name,
                    output=json.dumps(results, indent=2),
                    success=True,
                )

            elif name == "search_graph_context":
                symbol = args.get("symbol_name", "")
                context = self.env.search_graph_context(symbol)
                return AgentToolResult(
                    call_id=tool_call.call_id,
                    name=name,
                    output=json.dumps(context, indent=2),
                    success=True,
                )

            elif name == "edit_file":
                rel = args.get("relative_path", "")
                old_str = args.get("old_str", "")
                new_str = args.get("new_str", "")
                ok = self.env.apply_replacement(rel, old_str, new_str)
                if ok:
                    return AgentToolResult(
                        call_id=tool_call.call_id,
                        name=name,
                        output=f"Successfully applied edit to {rel}",
                        success=True,
                    )
                else:
                    LOGGER.info("edit_file no_match rel=%s old_str=%s", rel, old_str[:200])
                    return AgentToolResult(
                        call_id=tool_call.call_id,
                        name=name,
                        output=f"Failed to find exact match for old_str in {rel}. Re-read the file to check line content and whitespace.",
                        success=False,
                        error="no_match",
                    )

            elif name == "add_import":
                rel = args.get("relative_path", "")
                stmt = args.get("import_statement", "")
                ok = self.env.add_import(rel, stmt)
                return AgentToolResult(
                    call_id=tool_call.call_id,
                    name=name,
                    output=f"Successfully ensured import '{stmt}' in {rel}",
                    success=True,
                )

            elif name == "run_verification":
                status = self.env.run_full_verification(self.target_rule_id)
                summary: dict[str, Any] = {
                    "compile_passed": status.compile_passed,
                    "compile_output": status.compile_output if not status.compile_passed else "0 compilation errors",
                    "tests_passed": status.tests_passed,
                    "test_output": status.test_output if not status.tests_passed else "All tests passed",
                    "policy_passed": status.policy_passed,
                    "remaining_rule_violations": status.remaining_violations,
                    "all_3_gates_passed": status.all_passed,
                }
                if not status.policy_passed and status.policy_findings:
                    summary["policy_findings"] = status.policy_findings
                    summary["policy_guidance"] = (
                        "The Policy Gate rejected the candidate because untrusted taint still reaches a vulnerable sink. "
                        "To clear taint, avoid passing tainted variables to sink arguments. Use parameter binding "
                        "(e.g. PreparedStatement, XPathVariableResolver) or standard library sanitizers (e.g. ESAPI encoder)."
                    )
                summary["next_step"] = (
                    "All 3 gates passed! Please call 'finish_remediation' now with a clear summary explanation."
                    if status.all_passed
                    else "Verification failed. Please read the errors and guidance above, adjust your patch with 'edit_file', and verify again."
                )
                return AgentToolResult(
                    call_id=tool_call.call_id,
                    name=name,
                    output=json.dumps(summary, indent=2),
                    success=True,
                )

            elif name in {"finish_remediation", "refuse_remediation"}:
                reason = args.get("reason", "")
                return AgentToolResult(call_id=tool_call.call_id, name=name, output=reason, success=True)

            else:
                return AgentToolResult(
                    call_id=tool_call.call_id,
                    name=name,
                    output=f"Unknown tool: {name}",
                    success=False,
                    error="unknown_tool",
                )
        except Exception as exc:
            return AgentToolResult(
                call_id=tool_call.call_id,
                name=name,
                output=f"Tool execution failed: {exc}",
                success=False,
                error=str(exc),
            )
