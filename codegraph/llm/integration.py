"""Compatibility facade for explanation generation."""

from codegraph.llm.services.explanation_service import (
    explain_policy_violations,
    generate_policy_explanation,
    generate_policy_explanation_structured,
)
from codegraph.llm.schema.explanation import render_policy_explanation_structured

__all__ = [
    "explain_policy_violations",
    "generate_policy_explanation",
    "generate_policy_explanation_structured",
    "render_policy_explanation_structured",
]
