from pydantic import BaseModel
from typing import List, Optional

class UploadResponse(BaseModel):
    status: str
    java_root: Optional[str] = None
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
    controls: list
    error: Optional[str] = None

class PolicyEvaluateWithLLMRequest(BaseModel):
    limit: int = 10
    model: Optional[str] = None


class RemediationRequest(BaseModel):
    violation_id: str


class RemediationResponse(BaseModel):
    status: str
    original_file: Optional[str] = None
    patched_file: Optional[str] = None
    diff: Optional[str] = None
    verification: Optional[dict] = None
    error: Optional[str] = None


class RemediationRunRequest(BaseModel):
    violation_id: str
    max_attempts: int | None = 3
    target_method: Optional[str] = None
    file_path: Optional[str] = None


class RemediationRunResponse(BaseModel):
    id: str
    violation_id: str
    state: str
    file_path: Optional[str] = None
    rule_id: Optional[str] = None
    target_method: Optional[str] = None
    attempts: int
    max_attempts: int
    patch: Optional[str] = None
    raw_llm_output: Optional[str] = None
    explanation: Optional[str] = None
    compile_error: Optional[str] = None
    policy_error: Optional[str] = None
    verification: Optional[dict] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    errors: Optional[list[str]] = None
    status: Optional[str] = None
