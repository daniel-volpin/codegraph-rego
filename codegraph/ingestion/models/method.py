from typing import List, Optional

from pydantic import BaseModel, Field


class MethodEntity(BaseModel):
    class_fqn: str
    signature: str
    full_signature: Optional[str] = None
    name: str
    params: List[str] = Field(default_factory=list)
    annotations: List[str] = Field(default_factory=list)
    return_type: Optional[str]
    modifiers: List[str] = Field(default_factory=list)
    file_path: str
    calls: List[str] = Field(default_factory=list)
    uses: List[str] = Field(default_factory=list)
    start_line: Optional[int] = None
    end_line: Optional[int] = None
