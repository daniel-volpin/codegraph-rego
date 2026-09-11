"""Remediation package: single-method bounded and multi-turn autonomous remediation engines."""

from __future__ import annotations

from typing import TYPE_CHECKING

from codegraph.remediation.capabilities import (
    RemediationCapability,
    default_supported_remediation_rule_ids,
    get_remediation_capability,
    remediation_capability_dict,
)
from codegraph.remediation.editing import unified_diff

if TYPE_CHECKING:
    from codegraph.remediation.agentic import AgenticRemediationService
    from codegraph.remediation.orchestration import (
        apply_remediation,
        preview_virtual_remediation,
        run_agentic_remediation,
    )
    from codegraph.remediation.service import RemediationService

__all__ = [
    "AgenticRemediationService",
    "RemediationCapability",
    "RemediationService",
    "apply_remediation",
    "default_supported_remediation_rule_ids",
    "get_remediation_capability",
    "preview_virtual_remediation",
    "remediation_capability_dict",
    "run_agentic_remediation",
    "unified_diff",
]


def __getattr__(name: str):
    if name == "RemediationService":
        from codegraph.remediation.service import RemediationService

        return RemediationService
    if name in {"apply_remediation", "preview_virtual_remediation", "run_agentic_remediation"}:
        from codegraph.remediation import orchestration

        return getattr(orchestration, name)
    if name == "AgenticRemediationService":
        from codegraph.remediation.agentic import AgenticRemediationService

        return AgenticRemediationService
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
