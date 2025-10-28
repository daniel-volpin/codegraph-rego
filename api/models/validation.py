from pydantic import BaseModel
from typing import List, Optional

class UploadResponse(BaseModel):
    status: str
    java_root: Optional[str] = None
    error: Optional[str] = None

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
