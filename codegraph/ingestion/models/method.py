
from pydantic import BaseModel, Field


class MethodEntity(BaseModel):
    class_fqn: str
    signature: str
    full_signature: str | None = None
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
