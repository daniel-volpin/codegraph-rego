"""Autonomous agentic remediation framework."""

from __future__ import annotations

from codegraph.remediation.agentic.agent import AgenticRemediationService
from codegraph.remediation.agentic.contracts import (
    AgentOutcomeStatus,
    AgentRemediationResult,
    AgentToolCall,
    AgentToolResult,
    AgentTurn,
    AgentVerificationStatus,
)
from codegraph.remediation.agentic.environment import IsolatedWorktreeEnvironment
from codegraph.remediation.agentic.tools import AGENT_TOOL_DEFINITIONS, AgentToolExecutor

__all__ = [
    "AgentOutcomeStatus",
    "AgentRemediationResult",
    "AgentToolCall",
    "AgentToolExecutor",
    "AgentToolResult",
    "AgentTurn",
    "AgentVerificationStatus",
    "AgenticRemediationService",
    "IsolatedWorktreeEnvironment",
    "AGENT_TOOL_DEFINITIONS",
]
