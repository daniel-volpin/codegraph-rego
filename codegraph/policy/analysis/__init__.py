"""Static analysis package for security and policy rule evaluation."""

from __future__ import annotations

from codegraph.policy.analysis.boolean_eval import evaluate_constant_boolean
from codegraph.policy.analysis.command import CommandAnalysis, CommandFlowAnalyzer
from codegraph.policy.analysis.conditional import ConditionalAssignmentResolver
from codegraph.policy.analysis.crypto import CryptoAnalysis, CryptoIndicatorAnalyzer
from codegraph.policy.analysis.injection import (
    LDAPAnalysis,
    LDAPSafetyAnalyzer,
    PathAnalysis,
    PathSafetyAnalyzer,
    SQLAnalysis,
    SQLSafetyAnalyzer,
    XPathAnalysis,
    XPathSafetyAnalyzer,
)
from codegraph.policy.analysis.state import AssignmentState, AssignmentStateAnalyzer

__all__ = [
    "AssignmentState",
    "AssignmentStateAnalyzer",
    "CommandAnalysis",
    "CommandFlowAnalyzer",
    "ConditionalAssignmentResolver",
    "CryptoAnalysis",
    "CryptoIndicatorAnalyzer",
    "LDAPAnalysis",
    "LDAPSafetyAnalyzer",
    "PathAnalysis",
    "PathSafetyAnalyzer",
    "SQLAnalysis",
    "SQLSafetyAnalyzer",
    "XPathAnalysis",
    "XPathSafetyAnalyzer",
    "evaluate_constant_boolean",
]
