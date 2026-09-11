
from pydantic import BaseModel, Field


class MethodEntity(BaseModel):
    method_key: str
    declaring_type_key: str
    workspace_id: str
    revision_id: str
    relative_path: str
    class_fqn: str | None = None
    signature: str
    full_signature: str
    name: str
    params: list[str] = Field(default_factory=list)
    annotations: list[str] = Field(default_factory=list)
    return_type: str | None
    modifiers: list[str] = Field(default_factory=list)
    file_path: str
    calls: list[str] = Field(default_factory=list)
    uses: list[str] = Field(default_factory=list)
    start_line: int | None = None
    end_line: int | None = None
    start_byte: int | None = None
    end_byte: int | None = None
    source_sha256: str
    parser_backend: str
    parser_version: str
    adapter_version: str
    language_level: str | None = None
    resolution_status: str
    binding_origin: str
    resolved_binding_key: str | None = None
    resolved_descriptor: str | None = None
    range_status: str
