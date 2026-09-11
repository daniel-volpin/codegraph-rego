from pydantic import BaseModel, Field


class ClassEntity(BaseModel):
    type_key: str
    workspace_id: str
    revision_id: str
    relative_path: str
    fqn: str | None = None
    binary_name: str | None = None
    name: str
    kind: str
    nesting_path: list[str] = Field(default_factory=list)
    enclosing_type_key: str | None = None
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
