from __future__ import annotations

from enum import StrEnum
from typing import Any, TypedDict

from pydantic import BaseModel, Field, model_validator


class ArtifactKind(StrEnum):
    PATCH = "patch"
    EXECUTABLE_SCAFFOLD = "executable_scaffold"
    STRUCTURED_REPAIR_PLAN = "structured_repair_plan"
    NONE = "none"


class Disposition(StrEnum):
    AUTO_APPLY = "auto_apply"
    REVIEW_REQUIRED = "review_required"
    MANUAL_EXECUTION_REQUIRED = "manual_execution_required"
    ABSTAIN = "abstain"


class ValidatorState(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"
    ERROR = "ERROR"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class LifecycleReasonCode(StrEnum):
    UNSUPPORTED_REPAIR_PATTERN = "unsupported_repair_pattern"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    UNRESOLVED_PROJECT_POLICY_DEPENDENCY = "unresolved_project_policy_dependency"
    TRANSFORMATION_FAILURE = "transformation_failure"
    PIPELINE_VERIFICATION_FAILURE = "pipeline_verification_failure"
    SEMANTIC_VERIFICATION_FAILURE = "semantic_verification_failure"
    SAFETY_GATE_REJECTION = "safety_gate_rejection"


class NearMissKind(StrEnum):
    DYNAMIC_IDENTIFIER = "dynamic_identifier"
    DYNAMIC_ORDER_BY = "dynamic_order_by"
    DYNAMIC_OPERATOR = "dynamic_operator"
    DYNAMIC_CLAUSE = "dynamic_clause"
    RESIDUAL_DYNAMIC_SQL = "residual_dynamic_sql"


class TransformationStrategy(StrEnum):
    TYPED_STRUCTURED_EDITS = "typed_structured_edits"
    AST_AWARE = "ast_aware"
    PATCH_COMPILER = "patch_compiler"
    BOUNDED_DETERMINISTIC_TEXT = "bounded_deterministic_text"


class ValidatorResult(BaseModel):
    validator_id: str
    state: ValidatorState
    required: bool = True
    message: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class PatchArtifact(BaseModel):
    format: str = "structured_edits"
    target_file: str
    anchor_method: str
    edits: list[dict[str, Any]] = Field(default_factory=list)
    updated_source_code: str | None = None
    diff: str | None = None


class ExecutableScaffoldArtifact(BaseModel):
    summary: str
    commands: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)


class StructuredRepairPlanArtifact(BaseModel):
    summary: str
    steps: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)


class ShadowError(BaseModel):
    code: str
    message: str
    details: dict[str, Any] = Field(default_factory=dict)


class ShadowRemediationLifecycle(BaseModel):
    plugin_id: str
    plugin_version: str
    supported_rule_id: str
    language: str
    repair_pattern_id: str | None = None
    repair_pattern_version: str | None = None
    transformation_strategy: TransformationStrategy
    artifact_kind: ArtifactKind
    disposition: Disposition
    recommended_disposition: Disposition
    effective_runtime_mode: str = "shadow_only"
    pipeline_verified: bool = False
    assurance_verified: bool = False
    auto_apply_eligible: bool = False
    evidence_complete: bool = False
    project_policy_dependency_resolved: bool = True
    patch_artifact: PatchArtifact | None = None
    executable_scaffold: ExecutableScaffoldArtifact | None = None
    structured_repair_plan: StructuredRepairPlanArtifact | None = None
    near_miss_classification: NearMissKind | None = None
    reason_codes: list[LifecycleReasonCode] = Field(default_factory=list)
    pipeline_checks: list[ValidatorResult] = Field(default_factory=list)
    semantic_validators: list[ValidatorResult] = Field(default_factory=list)
    reproducibility_key: str
    shadow_error: ShadowError | None = None

    @staticmethod
    def _mandatory_semantic_validators_pass(validators: list[ValidatorResult]) -> bool:
        mandatory = [validator for validator in validators if validator.required]
        if not mandatory:
            return False
        return all(validator.state == ValidatorState.PASS for validator in mandatory)

    @model_validator(mode="after")
    def validate_invariants(self) -> ShadowRemediationLifecycle:
        artifact_payload_count = sum(
            payload is not None
            for payload in (self.patch_artifact, self.executable_scaffold, self.structured_repair_plan)
        )

        if self.artifact_kind == ArtifactKind.PATCH:
            if self.patch_artifact is None or self.executable_scaffold is not None or self.structured_repair_plan is not None:
                raise ValueError("artifact_kind=patch requires only patch_artifact")
        elif self.artifact_kind == ArtifactKind.EXECUTABLE_SCAFFOLD:
            if (
                self.executable_scaffold is None
                or self.patch_artifact is not None
                or self.structured_repair_plan is not None
            ):
                raise ValueError("artifact_kind=executable_scaffold requires only executable_scaffold")
        elif self.artifact_kind == ArtifactKind.STRUCTURED_REPAIR_PLAN:
            if (
                self.structured_repair_plan is None
                or self.patch_artifact is not None
                or self.executable_scaffold is not None
            ):
                raise ValueError("artifact_kind=structured_repair_plan requires only structured_repair_plan")
        elif self.artifact_kind == ArtifactKind.NONE and artifact_payload_count != 0:
            raise ValueError("artifact_kind=none forbids artifact payloads")

        if self.auto_apply_eligible and not self._mandatory_semantic_validators_pass(self.semantic_validators):
            raise ValueError("auto_apply_eligible=true requires all mandatory semantic validators to PASS")

        if self.assurance_verified:
            if not self.pipeline_verified:
                raise ValueError("assurance_verified=true requires pipeline_verified=true")
            if not self.evidence_complete:
                raise ValueError("assurance_verified=true requires complete evidence")
            if not self.project_policy_dependency_resolved:
                raise ValueError("assurance_verified=true requires resolved project policy dependencies")
            if not self._mandatory_semantic_validators_pass(self.semantic_validators):
                raise ValueError("assurance_verified=true requires all mandatory semantic validators to PASS")
            if any(
                code in {
                    LifecycleReasonCode.UNRESOLVED_PROJECT_POLICY_DEPENDENCY,
                    LifecycleReasonCode.SEMANTIC_VERIFICATION_FAILURE,
                    LifecycleReasonCode.PIPELINE_VERIFICATION_FAILURE,
                    LifecycleReasonCode.SAFETY_GATE_REJECTION,
                }
                for code in self.reason_codes
            ):
                raise ValueError("assurance_verified=true forbids blocking reason codes")

        if self.auto_apply_eligible and not self.assurance_verified:
            raise ValueError("auto_apply_eligible=true requires assurance_verified=true")

        if self.disposition == Disposition.AUTO_APPLY:
            if self.artifact_kind != ArtifactKind.PATCH or self.patch_artifact is None:
                raise ValueError("disposition=auto_apply requires patch artifact")
            if not self.pipeline_verified or not self.assurance_verified or not self.auto_apply_eligible:
                raise ValueError(
                    "disposition=auto_apply requires pipeline_verified, assurance_verified, and auto_apply_eligible"
                )

        return self


class CompilationResult(TypedDict, total=False):
    attempted: bool
    success: bool
    output_snippet: str | None
    skipped_reason: str | None


class ApplyMetadata(TypedDict):
    violation_id: str
    rule_id: str | None
    target_method: str
    file_path: str
    attempt_count: int
    mode: str


class _ApplyFixResultRequired(TypedDict):
    status: str
    violation_id: str


class ApplyFixResult(_ApplyFixResultRequired, total=False):
    error: str | None
    rule_id: str | None
    target_method: str | None
    file_path: str | None
    updated_source_code: str | None
    diff: str | None
    verification: dict[str, Any]
    compilation: CompilationResult
    metadata: ApplyMetadata
    generation: dict[str, Any] | None
    confidence: dict[str, Any]
    attempt_count: int
    llm_output: Any
    errors: list[str]
    raw_capture_files: list[str]
    predicate_trace: dict[str, Any] | None
    shadow_lifecycle: dict[str, Any]
    shadow_comparison: dict[str, Any]


def early_error_result(
    status: str,
    *,
    violation_id: str,
    error: str,
    rule_id: Any = None,
    target_method: str | None = None,
    file_path: str | None = None,
) -> ApplyFixResult:
    result: ApplyFixResult = {
        "status": status,
        "violation_id": violation_id,
        "error": error,
    }
    if rule_id is not None:
        result["rule_id"] = rule_id
    if target_method is not None:
        result["target_method"] = target_method
    if file_path is not None:
        result["file_path"] = file_path
    return result


def generation_error_result(
    status: str,
    *,
    violation_id: str,
    error: str,
    target_method: str,
    file_path: str,
    rule_id: Any,
    attempt_count: int,
    llm_output: Any,
    errors: list[str],
    raw_capture_files: list[str],
    generation: dict[str, Any] | None,
    confidence: dict[str, Any],
) -> ApplyFixResult:
    return {
        "status": status,
        "error": error,
        "violation_id": violation_id,
        "target_method": target_method,
        "file_path": file_path,
        "rule_id": rule_id,
        "attempt_count": attempt_count,
        "llm_output": llm_output,
        "errors": errors,
        "raw_capture_files": raw_capture_files,
        "generation": generation,
        "confidence": confidence,
    }


def partial_error_result(
    *,
    violation_id: str,
    error: str,
    target_method: str,
    file_path: str,
    rule_id: Any,
    updated_source_code: str | None = None,
    diff: str | None = None,
    compilation: CompilationResult | None = None,
    generation: dict[str, Any] | None = None,
    confidence: dict[str, Any] | None = None,
    predicate_trace: dict[str, Any] | None = None,
) -> ApplyFixResult:
    result: ApplyFixResult = {
        "status": "VERIFICATION_ERROR",
        "error": error,
        "violation_id": violation_id,
        "target_method": target_method,
        "file_path": file_path,
        "rule_id": rule_id,
    }
    if updated_source_code is not None:
        result["updated_source_code"] = updated_source_code
    if diff is not None:
        result["diff"] = diff
    if compilation is not None:
        result["compilation"] = compilation
    if generation is not None:
        result["generation"] = generation
    if confidence is not None:
        result["confidence"] = confidence
    if predicate_trace is not None:
        result["predicate_trace"] = predicate_trace
    return result


def apply_result(
    status: str,
    *,
    violation_id: str,
    rule_id: Any,
    target_method: str,
    file_path: str,
    updated_source_code: str,
    diff: str,
    verification: dict[str, Any],
    compilation: CompilationResult,
    metadata: ApplyMetadata,
    generation: dict[str, Any] | None,
    confidence: dict[str, Any],
    error: str | None,
    predicate_trace: dict[str, Any] | None = None,
) -> ApplyFixResult:
    """Full apply-flow result (OK, BUILD_ERROR, or final VERIFICATION_ERROR)."""
    result: ApplyFixResult = {
        "status": status,
        "violation_id": violation_id,
        "rule_id": rule_id,
        "target_method": target_method,
        "file_path": file_path,
        "updated_source_code": updated_source_code,
        "diff": diff,
        "verification": verification,
        "compilation": compilation,
        "metadata": metadata,
        "generation": generation,
        "confidence": confidence,
        "error": error,
    }
    if predicate_trace is not None:
        result["predicate_trace"] = predicate_trace
    return result
