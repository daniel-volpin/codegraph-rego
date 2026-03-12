from pydantic import BaseModel, Field
from typing import Any, List, Literal, Optional


class UploadResponse(BaseModel):
    status: str
    java_root: Optional[str] = None
    java_roots: List[str] = Field(default_factory=list)
    error: Optional[str] = None


class UploadStatusResponse(BaseModel):
    phase: str
    message: str
    progress: float
    complete: bool
    error: Optional[str] = None
    updated_at: str
    started_at: Optional[str] = None


class HealthCheckResponse(BaseModel):
    neo4j: bool
    faiss_index: bool
    signature_map: bool
    embedding_model: bool
    opa: bool
    details: dict


class SearchRequest(BaseModel):
    query: str


class SearchMatch(BaseModel):
    method: str
    neighbors: List[dict]


class SearchResponse(BaseModel):
    matches: List[str]
    contexts: List[List[SearchMatch]]


class PolicyEvaluateResponse(BaseModel):
    violations: Optional[list] = None
    opa_output: Optional[dict] = None
    error: Optional[str] = None


class PolicyCatalogResponse(BaseModel):
    controls: List[dict] = Field(default_factory=list)
    rules: List[dict] = Field(default_factory=list)
    benchmark_categories: List[dict] = Field(default_factory=list)
    framework_demo_rule_ids: List[str] = Field(default_factory=list)
    error: Optional[str] = None


class PolicyEvaluateWithLLMRequest(BaseModel):
    limit: int = 10
    model: Optional[str] = None
    max_bundles: Optional[int] = None
    max_total_violations: Optional[int] = None
    max_per_violation_id: Optional[int] = None
    rule_ids: Optional[List[str]] = None


class PolicyExplainOneRequest(BaseModel):
    violation: dict
    include_graph_context: bool = True
    model: Optional[str] = None


class PolicyExplanationStructured(BaseModel):
    citation: str
    why: str
    fix: str


class PolicyExplainOneResponse(BaseModel):
    status: Literal["OK", "ERROR"]
    explanation: Optional[str] = None
    explanation_structured: Optional[PolicyExplanationStructured] = None
    model: Optional[str] = None
    include_graph_context: bool = True
    error: Optional[str] = None


class PolicyReviewCreateRequest(BaseModel):
    label: Literal["TP", "FP", "UNCLEAR"]
    notes: Optional[str] = None
    violation: dict
    explanation: Optional[str] = None
    llm_model: Optional[str] = None
    include_graph_context: bool = True
    remediation_preview: Optional[dict] = None
    remediation_apply: Optional[dict] = None


class PolicyReviewCreateResponse(BaseModel):
    status: Literal["OK", "ERROR"]
    review_id: Optional[str] = None
    store_path: Optional[str] = None
    scrub_warnings: List[str] = Field(default_factory=list)
    error: Optional[str] = None


class PolicyReviewListResponse(BaseModel):
    status: Literal["OK", "ERROR"]
    reviews: List[dict] = Field(default_factory=list)
    error: Optional[str] = None


class RemediationPreviewRequest(BaseModel):
    violation_id: str
    target_method: Optional[str] = None
    file_path: Optional[str] = None


class RemediationEditResponse(BaseModel):
    start_line: int
    end_line: int
    original_lines: List[str]
    replacement_lines: List[str]


class RemediationGenerationResponse(BaseModel):
    decision: Optional[Literal["apply_edits", "no_fix"]] = None
    edits: Optional[List[RemediationEditResponse]] = None
    replacement_method_lines: Optional[List[str]] = None
    replacement_method_code: Optional[str] = None
    reason: Optional[str] = None
    raw_response_valid: bool = False
    schema_error: Optional[str] = None


class RemediationPreviewResponse(BaseModel):
    status: str
    violation_id: str
    rule_id: Optional[str] = None
    target_method: Optional[str] = None
    file_path: Optional[str] = None
    updated_source_code: Optional[str] = None
    explanation: Optional[str] = None
    opa_status: Optional[str] = None
    opa_details: Optional[Any] = None
    diff: Optional[str] = None
    verification: Optional[dict] = None
    generation: Optional[RemediationGenerationResponse] = None
    error: Optional[str] = None


class RemediationApplyRequest(BaseModel):
    violation_id: str
    target_method: Optional[str] = None
    file_path: Optional[str] = None
    mode: str = "dry_run"
    max_attempts: int = 2


class RemediationApplyResponse(BaseModel):
    status: str
    violation_id: str
    rule_id: Optional[str] = None
    target_method: Optional[str] = None
    file_path: Optional[str] = None
    updated_source_code: Optional[str] = None
    diff: Optional[str] = None
    verification: Optional[dict] = None
    compilation: Optional[dict] = None
    metadata: Optional[dict] = None
    generation: Optional[RemediationGenerationResponse] = None
    error: Optional[str] = None
