
from pydantic import BaseModel, Field


class FieldEntity(BaseModel):
    class_fqn: str
    name: str
    type: str | None = None
    modifiers: list[str] = Field(default_factory=list)
    annotations: list[str] = Field(default_factory=list)
    file_path: str
    start_line: int | None = None
    end_line: int | None = None
