"""
Hybrid search internals: cached loaders, semantic search over FAISS, and
graph context retrieval via Neo4j. Extracted from hybrid_code_search to
reduce coupling with scripts and enable reuse from services and API.
"""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Any

from neo4j import Driver

from codegraph.config import settings

if TYPE_CHECKING:
    from sentence_transformers import SentenceTransformer

os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

# In-process caches
_INDEX: Any | None = None
_INDEX_MTIME: tuple[str, int, int] | None = None
_SIGMAP: list[str] | None = None
_SIGMAP_MTIME: tuple[str, int, int] | None = None
_MODEL: SentenceTransformer | None = None
_MODEL_NAME: str | None = None
_MODEL_LOCK = threading.Lock()
_ARTIFACT_LOCK = threading.Lock()


def load_faiss_index(index_path: str | None = None):
    global _INDEX, _INDEX_MTIME
    path = Path(index_path or settings.faiss_index_path).resolve()
    with _ARTIFACT_LOCK:
        stat = path.stat()
        identity = (str(path), stat.st_mtime_ns, stat.st_size)
        if _INDEX is not None and _INDEX_MTIME == identity:
            return _INDEX
        import faiss

        _INDEX = faiss.read_index(str(path))
        _INDEX_MTIME = identity
        return _INDEX


def load_signature_map(map_path: str | None = None) -> list[str]:
    global _SIGMAP, _SIGMAP_MTIME
    candidates = [map_path] if map_path is not None else [settings.signature_map_path_full, settings.signature_map_path]
    for candidate in candidates:
        path = Path(candidate).resolve()
        if not path.is_file():
            continue
        with _ARTIFACT_LOCK:
            stat = path.stat()
            identity = (str(path), stat.st_mtime_ns, stat.st_size)
            if _SIGMAP is not None and _SIGMAP_MTIME == identity:
                return _SIGMAP
            with path.open(encoding="utf-8") as handle:
                payload = json.load(handle)
            if not isinstance(payload, list) or any(not isinstance(value, str) or not value for value in payload):
                raise ValueError(f"Invalid signature map at {path}: expected a list of method identifiers")
            _SIGMAP = payload
            _SIGMAP_MTIME = identity
            return _SIGMAP
    raise FileNotFoundError(f"Signature map not found. Tried: {', '.join(candidates)}")


def load_embedding_model(model_name: str | None = None) -> SentenceTransformer:
    global _MODEL, _MODEL_NAME
    model_name = model_name or settings.embedding_model_name

    with _MODEL_LOCK:
        if _MODEL is None or _MODEL_NAME != model_name:
            from sentence_transformers import SentenceTransformer

            _MODEL = SentenceTransformer(model_name)
            _MODEL_NAME = model_name
        return _MODEL


def semantic_search(query: str, model: SentenceTransformer, index, signature_map: list[str], k: int = 5) -> list[str]:
    if k < 1:
        raise ValueError("Search result count must be positive")
    if index.ntotal != len(signature_map):
        raise ValueError("FAISS index and signature map have different method counts")
    if not signature_map:
        return []
    query_vector = model.encode([query], normalize_embeddings=True)
    _, indices = index.search(query_vector, k=min(k, len(signature_map)))
    return list(dict.fromkeys(signature_map[i] for i in indices[0] if 0 <= i < len(signature_map)))


def fetch_graph_context_for_method(sig: str, neo4j_driver: Driver) -> list[dict[str, Any]]:
    with neo4j_driver.session() as session:
        cypher = """
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
        result = session.run(cypher, sig=sig)
        return [record.data() for record in result]
