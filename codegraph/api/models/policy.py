from typing import Any, List, Optional
from pydantic import BaseModel, Field


class ControlMetadata(BaseModel):
    id: Optional[str] = None
    control: Optional[str] = None
    title: Optional[str] = None
    reference: Optional[str] = None
    summary: Optional[str] = None
    rego_module: Optional[str] = Field(default=None, alias="rego_module")
    rego_rule: Optional[str] = Field(default=None, alias="rego_rule")
    evidence_fields: Optional[List[str]] = None


class PolicyViolation(BaseModel):
    standard: Optional[str] = None
    id: Optional[str] = None
    method: Optional[str] = None
    file_path: Optional[str] = None
    reason: Optional[str] = None
    control_metadata: Optional[ControlMetadata] = None


class EvaluateResponse(BaseModel):
    violations: List[PolicyViolation]
    opa_output: Any
    catalog: List[ControlMetadata]


class LLMEnrichedItem(BaseModel):
    violation: PolicyViolation
    snippet: str
    explanation: str


class EvaluateWithLLMResponse(BaseModel):
    violations: List[PolicyViolation]
    enriched: List[LLMEnrichedItem]


class PolicyCatalogResponse(BaseModel):
    controls: List[ControlMetadata]
