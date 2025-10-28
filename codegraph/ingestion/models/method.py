from typing import List, Optional
from pydantic import BaseModel

class MethodEntity(BaseModel):
    class_fqn: str
    signature: str
    full_signature: Optional[str] = None
    name: str
    params: List[str]
    annotations: List[str]
    return_type: Optional[str]
    modifiers: List[str]
    file_path: str
    calls: List[str] = []
    uses: List[str] = []
