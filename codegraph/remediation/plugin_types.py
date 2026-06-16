from __future__ import annotations

from typing import Any, Protocol

from pydantic import BaseModel, Field

from codegraph.remediation.repair_intent import RepairIntent
from codegraph.remediation.result_models import (
    ArtifactKind,
    Disposition,
    ExecutableScaffoldArtifact,
    LifecycleReasonCode,
    StructuredRepairPlanArtifact,
    TransformationStrategy,
)
from codegraph.remediation.verification import BuildRequirement


class PipelineVerificationContract(BaseModel):
    build_requirement: BuildRequirement = BuildRequirement.IF_BUILD_SYSTEM_PRESENT
    require_parse: bool = True
    require_policy_recheck: bool = True


class RepairPatternContract(BaseModel):
    pattern_id: str
    pattern_version: str
    repair_patterns: list[str] = Field(default_factory=list)
    required_evidence: list[str] = Field(default_factory=list)
    project_policy_dependencies: list[str] = Field(default_factory=list)
    transformation_strategy: TransformationStrategy
    max_edit_scope_lines: int
    mandatory_semantic_validators: list[str] = Field(default_factory=list)
    pipeline_verification: PipelineVerificationContract = Field(default_factory=PipelineVerificationContract)
    auto_apply_capable: bool = True
    fallback_artifact_kind: ArtifactKind = ArtifactKind.STRUCTURED_REPAIR_PLAN
    fallback_disposition: Disposition = Disposition.MANUAL_EXECUTION_REQUIRED


class PluginDescriptor(BaseModel):
    plugin_id: str
    plugin_version: str
    supported_languages: list[str] = Field(default_factory=list)
    supported_rule_ids: list[str] = Field(default_factory=list)
    patterns: list[RepairPatternContract] = Field(default_factory=list)


class PluginProposal(BaseModel):
    artifact_kind: ArtifactKind
    disposition: Disposition
    repair_intent: RepairIntent | None = None
    patch_pattern: RepairPatternContract | None = None
    executable_scaffold: ExecutableScaffoldArtifact | None = None
    structured_repair_plan: StructuredRepairPlanArtifact | None = None
    reason_codes: list[LifecycleReasonCode] = Field(default_factory=list)
    evidence_complete: bool = False
    project_policy_dependency_resolved: bool = True
    details: dict[str, Any] = Field(default_factory=dict)


class RemediationShadowPlugin(Protocol):
    descriptor: PluginDescriptor

    def supports(self, *, rule_id: str, language: str) -> bool: ...

    def propose(self, context: dict[str, Any]) -> PluginProposal: ...

    def evaluate_semantics(
        self,
        *,
        context: dict[str, Any],
        proposal: PluginProposal,
        updated_method_source: str | None,
    ) -> list[Any]: ...