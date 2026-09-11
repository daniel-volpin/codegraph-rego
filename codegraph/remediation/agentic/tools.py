"""Tools available to the autonomous remediation agent."""

from __future__ import annotations

import json

from codegraph.remediation.agentic.contracts import AgentToolCall, AgentToolResult
from codegraph.remediation.agentic.environment import IsolatedWorktreeEnvironment

AGENT_TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read the contents of a source or configuration file in the workspace.",
            "parameters": {
                "type": "object",
                "properties": {
                    "relative_path": {
                        "type": "string",
                        "description": "Relative path to the file from the workspace root (e.g. src/main/java/com/acme/Service.java).",
                    }
                },
                "required": ["relative_path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "edit_file",
            "description": "Replace an exact block of text in a file with updated code.",
            "parameters": {
                "type": "object",
                "properties": {
                    "relative_path": {
                        "type": "string",
                        "description": "Relative path to the file to edit.",
                    },
                    "old_str": {
                        "type": "string",
                        "description": "Exact consecutive lines to replace.",
                    },
                    "new_str": {
                        "type": "string",
                        "description": "The new replacement code.",
                    },
                },
                "required": ["relative_path", "old_str", "new_str"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "add_import",
            "description": "Add an import statement to a Java file cleanly below package declaration.",
            "parameters": {
                "type": "object",
                "properties": {
                    "relative_path": {
                        "type": "string",
                        "description": "Relative path to the Java file.",
                    },
                    "import_statement": {
                        "type": "string",
                        "description": "Full import statement (e.g. 'import java.sql.PreparedStatement;' or 'java.sql.PreparedStatement').",
                    },
                },
                "required": ["relative_path", "import_statement"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "find_files",
            "description": "Find files in the workspace matching a glob pattern (e.g. '**/*.java', 'pom.xml', '**/*Repository.java').",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Glob pattern (default: '**/*').",
                    }
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_code",
            "description": "Search for text or regex patterns across files in the workspace.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Regex or substring pattern to search for.",
                    }
                },
                "required": ["pattern"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_graph_context",
            "description": "Query the Neo4j knowledge graph for callers, callees, and field declarations of a method or type.",
            "parameters": {
                "type": "object",
                "properties": {
                    "symbol_name": {
                        "type": "string",
                        "description": "Name or signature of the method/type to query (e.g. 'getUserName' or 'SqlDemo').",
                    }
                },
                "required": ["symbol_name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_verification",
            "description": "Trigger the 3-gate verification pipeline on the current workspace: compilation, regression tests, and OPA policy evaluation.",
            "parameters": {
                "type": "object",
                "properties": {},
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "finish_remediation",
            "description": "Complete remediation and propose the candidate patch.",
            "parameters": {
                "type": "object",
                "properties": {
                    "reason": {
                        "type": "string",
                        "description": "Summary explanation of the changes made and why they are secure and semantically sound.",
                    }
                },
                "required": ["reason"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "refuse_remediation",
            "description": "Refuse automatic remediation if a safe, semantically sound fix cannot be determined without human design decisions.",
            "parameters": {
                "type": "object",
                "properties": {
                    "reason": {
                        "type": "string",
                        "description": "Detailed explanation of why safe automated remediation is impossible (e.g. missing path policy, breaking external API).",
                    }
                },
                "required": ["reason"],
            },
        },
    },
]


class AgentToolExecutor:
    """Executes tool calls against the sandboxed environment."""

    def __init__(self, env: IsolatedWorktreeEnvironment, target_rule_id: str) -> None:
        self.env = env
        self.target_rule_id = target_rule_id

    def execute(self, tool_call: AgentToolCall) -> AgentToolResult:
        name = tool_call.name
        args = tool_call.arguments
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
                summary = {
                    "compile_passed": status.compile_passed,
                    "compile_output": status.compile_output if not status.compile_passed else "0 compilation errors",
                    "tests_passed": status.tests_passed,
                    "test_output": status.test_output if not status.tests_passed else "All tests passed",
                    "policy_passed": status.policy_passed,
                    "remaining_rule_violations": status.remaining_violations,
                    "all_3_gates_passed": status.all_passed,
                }
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
