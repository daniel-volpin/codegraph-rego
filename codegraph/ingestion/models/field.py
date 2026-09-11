
from pydantic import BaseModel, Field


class FieldEntity(BaseModel):
    field_key: str
    declaring_type_key: str
    workspace_id: str
    revision_id: str
    relative_path: str
    class_fqn: str | None = None
    name: str
    type: str | None = None
    modifiers: list[str] = Field(default_factory=list)
    annotations: list[str] = Field(default_factory=list)
    file_path: str
    start_line: int | None = None
    end_line: int | None = None
    start_byte: int | None = None
    end_byte: int | None = None
    source_sha256: str
    parser_backend: str
    parser_version: str
    adapter_version: str
    resolution_status: str
    binding_origin: str
    binding_key: str | None = None
    range_status: str
