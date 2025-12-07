from typing import List, Optional

from pydantic import BaseModel, Field


class FieldEntity(BaseModel):
    class_fqn: str
    name: str
    type: Optional[str] = None
    modifiers: List[str] = Field(default_factory=list)
    annotations: List[str] = Field(default_factory=list)
    file_path: str
    start_line: Optional[int] = None
    end_line: Optional[int] = None
