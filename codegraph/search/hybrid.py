"""
Hybrid search internals: cached loaders, semantic search over FAISS, and
graph context retrieval via Neo4j. Extracted from hybrid_code_search to
reduce coupling with scripts and enable reuse from services and API.
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple
import json
import os

import faiss  # type: ignore
from sentence_transformers import SentenceTransformer
from neo4j import Driver

from codegraph.config import (
    FAISS_INDEX_PATH,
    SIGNATURE_MAP_PATH,
    SIGNATURE_MAP_PATH_FULL,
    EMBEDDING_MODEL_NAME,
)

# In-process caches
_INDEX: Any | None = None
_INDEX_MTIME: float | None = None
_SIGMAP: List[str] | None = None
_SIGMAP_MTIME: Tuple[str, float] | None = None
_MODEL: SentenceTransformer | None = None


def load_faiss_index(index_path: str = FAISS_INDEX_PATH):
    global _INDEX, _INDEX_MTIME
    if not os.path.isfile(index_path):
        raise FileNotFoundError(
            f"FAISS index not found at {index_path}. Build embeddings first."
        )
    mtime = os.path.getmtime(index_path)
    if _INDEX is not None and _INDEX_MTIME == mtime:
        return _INDEX
    _INDEX = faiss.read_index(index_path)
    _INDEX_MTIME = mtime
    return _INDEX


def load_signature_map(map_path: str = SIGNATURE_MAP_PATH) -> List[str]:
    global _SIGMAP, _SIGMAP_MTIME
    candidates = [SIGNATURE_MAP_PATH_FULL, map_path, SIGNATURE_MAP_PATH]
    last_exc: Exception | None = None
    for candidate in candidates:
        if not os.path.isfile(candidate):
            continue
        mtime = os.path.getmtime(candidate)
        if _SIGMAP is not None and _SIGMAP_MTIME == (candidate, mtime):
            return _SIGMAP
        try:
            with open(candidate, "r") as f:
                _SIGMAP = json.load(f)
            _SIGMAP_MTIME = (candidate, mtime)
            return _SIGMAP
        except Exception as exc:  # pragma: no cover
            last_exc = exc
    msg = f"Signature map not found. Tried: {', '.join(candidates)}"
    if last_exc:
        msg += f". Last error: {last_exc}"
    raise FileNotFoundError(msg)


def load_embedding_model(model_name: str = EMBEDDING_MODEL_NAME) -> SentenceTransformer:
    global _MODEL
    if _MODEL is None:
        _MODEL = SentenceTransformer(model_name)
    return _MODEL


def semantic_search(
    query: str, model: SentenceTransformer, index, signature_map: List[str], k: int = 5
) -> List[str]:
    query_vector = model.encode([query], normalize_embeddings=True)
    _, indices = index.search(query_vector, k=k)
    return [signature_map[i] for i in indices[0]]


def fetch_graph_context_for_method(sig: str, neo4j_driver: Driver) -> List[Dict[str, Any]]:
    with neo4j_driver.session() as session:
        cypher = (
            """
            MATCH (m:Method)
            WHERE m.signature = $sig OR m.full_signature = $sig
            MATCH path=(m)-[:CALLS|DECLARES|NESTED_IN*1..2]-(n)
            RETURN coalesce(m.full_signature, m.signature) AS method,
                   collect(DISTINCT CASE
                     WHEN n:Method THEN {type: 'Method', id: coalesce(n.full_signature, n.signature)}
                     WHEN n:Class  THEN {type: 'Class',  id: n.fqn}
                     ELSE {type: 'Node', id: coalesce(n.signature, n.fqn, n.name)}
                   END) AS neighbors
            """
        )
        result = session.run(cypher, sig=sig)
        return [record.data() for record in result]
