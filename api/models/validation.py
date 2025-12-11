from pydantic import BaseModel
from typing import Any, List, Optional

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


class RemediationPreviewRequest(BaseModel):
    violation_id: str
    target_method: Optional[str] = None
    file_path: Optional[str] = None


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
    error: Optional[str] = None
