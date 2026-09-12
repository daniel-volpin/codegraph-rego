"""Data contracts for the autonomous multi-turn agentic remediation engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

import json

AgentRole = Literal["system", "user", "assistant", "tool"]
AgentOutcomeStatus = Literal[
    "SUCCESS",
    "REFUSED",
    "MAX_TURNS_EXCEEDED",
    "VERIFICATION_FAILED",
    "COMPILATION_ERROR",
    "ERROR",
]


@dataclass(frozen=True)
class AgentToolCall:
    call_id: str
    name: str
    arguments: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.call_id,
            "type": "function",
            "function": {
                "name": self.name,
                "arguments": json.dumps(self.arguments) if isinstance(self.arguments, dict) else str(self.arguments),
            },
        }


@dataclass(frozen=True)
class AgentToolResult:
    call_id: str
    name: str
    output: str
    success: bool
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "call_id": self.call_id,
            "name": self.name,
            "output": self.output,
            "success": self.success,
            "error": self.error,
        }


@dataclass
class AgentTurn:
    role: AgentRole
    content: str = ""
    tool_calls: list[AgentToolCall] = field(default_factory=list)
    tool_results: list[AgentToolResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "content": self.content,
            "tool_calls": [tc.to_dict() for tc in self.tool_calls],
            "tool_results": [tr.to_dict() for tr in self.tool_results],
        }


@dataclass(frozen=True)
class AgentVerificationStatus:
    compile_passed: bool
    compile_output: str | None
    tests_passed: bool
    test_output: str | None
    policy_passed: bool
    policy_findings: list[dict[str, Any]]
    remaining_violations: list[str]

    @property
    def all_passed(self) -> bool:
        return self.compile_passed and self.tests_passed and self.policy_passed

    def to_dict(self) -> dict[str, Any]:
        return {
            "all_passed": self.all_passed,
            "compile_passed": self.compile_passed,
            "compile_output": self.compile_output,
            "tests_passed": self.tests_passed,
            "test_output": self.test_output,
            "policy_passed": self.policy_passed,
            "remaining_violations": self.remaining_violations,
            "policy_findings": self.policy_findings,
        }


@dataclass(frozen=True)
class AgentRemediationResult:
    status: AgentOutcomeStatus
    rule_id: str
    method_key: str
    target_method: str
    workspace_root: str
    modified_files: list[str]
    diff: str
    verification: AgentVerificationStatus | None
    turns: list[AgentTurn]
    reason: str
    iterations: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "rule_id": self.rule_id,
            "method_key": self.method_key,
            "target_method": self.target_method,
            "workspace_root": self.workspace_root,
            "modified_files": self.modified_files,
            "diff": self.diff,
            "verification": self.verification.to_dict() if self.verification else None,
            "reason": self.reason,
            "iterations": self.iterations,
            "turns_count": len(self.turns),
        }
