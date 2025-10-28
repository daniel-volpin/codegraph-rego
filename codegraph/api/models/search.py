from typing import List
from pydantic import BaseModel

class Neighbor(BaseModel):
    type: str
    id: str

class MethodContext(BaseModel):
    method: str
    neighbors: List[Neighbor]

class SearchResponse(BaseModel):
    matches: List[str]
    contexts: List[List[MethodContext]]
