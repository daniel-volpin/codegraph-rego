from typing import Any, Literal

from pydantic import BaseModel, Field


class HealthStartupStatus(BaseModel):
    ready: bool
    phase: Literal["pending", "running", "ready", "degraded"]
    checks: dict = Field(default_factory=dict)
    errors: dict = Field(default_factory=dict)


class LivenessResponse(BaseModel):
    """Liveness response: process is up; says nothing about dependencies."""

    status: Literal["alive"]


class UploadResponse(BaseModel):
    status: str
    java_root: str | None = None
    java_roots: list[str] = Field(default_factory=list)
    error: str | None = None
    request_id: str | None = None


class UploadStatusResponse(BaseModel):
    phase: str
    message: str
    progress: float
    complete: bool
    error: str | None = None
    updated_at: str
    started_at: str | None = None
    request_id: str | None = None


class HealthCheckResponse(BaseModel):
    status: Literal["ok", "degraded"]
    startup_ready: bool
    neo4j: bool
    faiss_index: bool
    signature_map: bool
    embedding_model: bool
    opa: bool
    startup: HealthStartupStatus
    details: dict


class SearchRequest(BaseModel):
    query: str


class SearchMatch(BaseModel):
    method: str
    neighbors: list[dict]


class SearchResponse(BaseModel):
    matches: list[str]
    contexts: list[list[SearchMatch]]


class PolicyEvaluateResponse(BaseModel):
    violations: list | None = None
    opa_output: dict | None = None
    error: str | None = None


class PolicyCatalogResponse(BaseModel):
    controls: list[dict] = Field(default_factory=list)
    rules: list[dict] = Field(default_factory=list)
    benchmark_categories: list[dict] = Field(default_factory=list)
    framework_demo_rule_ids: list[str] = Field(default_factory=list)
    error: str | None = None


class PolicyEvaluateWithLLMRequest(BaseModel):
    limit: int = 10
    model: str | None = None
    max_bundles: int | None = None
    max_total_violations: int | None = None
    max_per_violation_id: int | None = None
    rule_ids: list[str] | None = None


class PolicyExplainOneRequest(BaseModel):
    violation: dict
    include_graph_context: bool = True
    model: str | None = None


class PolicyExplanationStructured(BaseModel):
    evidence_id: str | None = None
    citation: str
    why: str
    fix: str


class PolicyExplainOneResponse(BaseModel):
    status: Literal["OK", "ERROR"]
    explanation: str | None = None
    explanation_structured: PolicyExplanationStructured | None = None
    model: str | None = None
    include_graph_context: bool = True
    error: str | None = None


class PolicyReviewCreateRequest(BaseModel):
    label: Literal["TP", "FP", "UNCLEAR"]
    notes: str | None = None
    violation: dict
    explanation: str | None = None
    llm_model: str | None = None
    include_graph_context: bool = True
    remediation_preview: dict | None = None
    remediation_apply: dict | None = None


class PolicyReviewCreateResponse(BaseModel):
    status: Literal["OK", "ERROR"]
    review_id: str | None = None
    store_path: str | None = None
    scrub_warnings: list[str] = Field(default_factory=list)
    error: str | None = None


class PolicyReviewListResponse(BaseModel):
    status: Literal["OK", "ERROR"]
    reviews: list[dict] = Field(default_factory=list)
    error: str | None = None


class RemediationPreviewRequest(BaseModel):
    violation_id: str
    target_method: str | None = None
    file_path: str | None = None


class RemediationEditResponse(BaseModel):
    start_line: int
    end_line: int
    original_lines: list[str]
    replacement_lines: list[str]


class RemediationGenerationResponse(BaseModel):
    decision: Literal["apply_edits", "no_fix"] | None = None
    edits: list[RemediationEditResponse] | None = None
    replacement_method_lines: list[str] | None = None
    replacement_method_code: str | None = None
    reason: str | None = None
    raw_response_valid: bool = False
    schema_error: str | None = None


class RemediationPreviewResponse(BaseModel):
    status: str
    violation_id: str
    rule_id: str | None = None
    target_method: str | None = None
    file_path: str | None = None
    updated_source_code: str | None = None
    explanation: str | None = None
    opa_status: str | None = None
    opa_details: Any | None = None
    diff: str | None = None
    verification: dict | None = None
    generation: RemediationGenerationResponse | None = None
    confidence: dict | None = None
    error: str | None = None


class RemediationApplyRequest(BaseModel):
    violation_id: str
    target_method: str | None = None
    file_path: str | None = None
    mode: str = "dry_run"
    max_attempts: int = 2


class RemediationApplyResponse(BaseModel):
    status: str
    violation_id: str
    rule_id: str | None = None
    target_method: str | None = None
    file_path: str | None = None
    updated_source_code: str | None = None
    diff: str | None = None
    verification: dict | None = None
    compilation: dict | None = None
    metadata: dict | None = None
    generation: RemediationGenerationResponse | None = None
    confidence: dict | None = None
    error: str | None = None
