from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Any

from neo4j import Driver

from codegraph.config import settings
from codegraph.search.artifacts import (
    ActiveEmbeddingGeneration,
    ArtifactConsistencyError,
    load_active_generation,
)

if TYPE_CHECKING:
    from sentence_transformers import SentenceTransformer

os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

_MODEL: SentenceTransformer | None = None
_MODEL_NAME: str | None = None
_MODEL_LOCK = threading.Lock()


def path_identity(path: Path) -> tuple[str, int, int]:
    stat = path.stat()
    return (str(path), stat.st_mtime_ns, stat.st_size)


def safe_setting(name: str, default: str | None = None) -> str | None:
    return getattr(settings, name, default)


def is_configured_index_path(path: Path) -> bool:
    configured = safe_setting("faiss_index_path")
    return configured is not None and path == Path(configured).resolve()


def is_configured_map_path(path: Path) -> bool:
    configured_full = safe_setting("signature_map_path_full")
    return configured_full is not None and path == Path(configured_full).resolve()


def resolve_active_generation(*, required: bool) -> ActiveEmbeddingGeneration | None:
    if not required:
        return None
    manifest_path = safe_setting("embedding_metadata_path")
    if not manifest_path:
        raise ArtifactConsistencyError(
            "Managed embedding artifacts require generation manifest configuration (embedding_metadata_path)."
        )
    path = Path(manifest_path).resolve()
    if not path.is_file():
        raise ArtifactConsistencyError(
            "Managed embedding artifacts require an active generation manifest. "
            f"Expected file at {path}. Rebuild embeddings before search."
        )
    try:
        return load_active_generation(path)
    except ArtifactConsistencyError as exc:
        raise ArtifactConsistencyError(
            "Managed embedding artifacts are inconsistent. Mixed index/map loading is disabled. "
            f"Rebuild embeddings to republish a complete generation. Details: {exc}"
        ) from exc


def read_method_key_map(path: Path) -> list[str]:
    with path.open(encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, list) or any(not isinstance(value, str) or not value for value in payload):
        raise ValueError(f"Invalid signature map at {path}: expected a list of method identifiers")
    return payload


def read_faiss_index(path: Path):
    import faiss  # noqa: PLC0415

    return faiss.read_index(str(path))


def load_embedding_model(model_name: str | None = None) -> SentenceTransformer:
    global _MODEL, _MODEL_NAME
    model_name = model_name or settings.embedding_model_name

    with _MODEL_LOCK:
        if _MODEL is None or _MODEL_NAME != model_name:
            from sentence_transformers import SentenceTransformer  # noqa: PLC0415

            _MODEL = SentenceTransformer(model_name)
            _MODEL_NAME = model_name
        return _MODEL


def semantic_search(
    query: str,
    model: SentenceTransformer,
    index,
    signature_map: list[str],
    k: int = 5,
    *,
    generation: ActiveEmbeddingGeneration | None = None,
    expected_model_name: str | None = None,
) -> list[str]:
    if k < 1:
        raise ValueError("Search result count must be positive")
    if index.ntotal != len(signature_map):
        raise ValueError("FAISS index and signature map have different method counts")
    if generation is not None and expected_model_name is not None and generation.model != expected_model_name:
        raise ValueError(
            f"Active embedding generation model mismatch: index built with {generation.model}, "
            f"requested model is {expected_model_name}"
        )
    if generation is not None and generation.dim is not None and hasattr(index, "d") and int(index.d) != generation.dim:
        raise ValueError(
            f"Active embedding generation dimension mismatch: manifest dim={generation.dim}, index dim={int(index.d)}"
        )
    if not signature_map:
        return []
    query_vector = model.encode([query], normalize_embeddings=True)
    if generation is not None and generation.dim is not None:
        encoded_dim = len(query_vector[0]) if query_vector is not None and len(query_vector) > 0 else None
        if encoded_dim != generation.dim:
            raise ValueError(
                f"Embedding query dimension mismatch: model produced dim={encoded_dim}, generation dim={generation.dim}"
            )
    _, indices = index.search(query_vector, k=min(k, len(signature_map)))
    return list(dict.fromkeys(signature_map[i] for i in indices[0] if 0 <= i < len(signature_map)))


def semantic_search_by_method_vector(method_key: str, index, signature_map: list[str], k: int = 5) -> list[str]:
    if k < 1:
        raise ValueError("Search result count must be positive")
    if index.ntotal != len(signature_map):
        raise ValueError("FAISS index and signature map have different method counts")
    if method_key not in signature_map:
        raise KeyError(f"method_key not found in active retrieval artifact: {method_key}")
    if not hasattr(index, "reconstruct"):
        raise RuntimeError("Active FAISS index cannot reconstruct stored vectors for method_key similarity.")
    position = signature_map.index(method_key)
    vector = index.reconstruct(position)
    import numpy as np  # noqa: PLC0415

    query_vector = np.asarray([vector], dtype="float32")
    _, indices = index.search(query_vector, k=min(k + 1, len(signature_map)))
    results: list[str] = []
    for idx in indices[0]:
        if 0 <= idx < len(signature_map):
            candidate = signature_map[idx]
            if candidate != method_key and candidate not in results:
                results.append(candidate)
        if len(results) >= k:
            break
    return results


def fetch_graph_context_for_method(method_key: str, neo4j_driver: Driver) -> list[dict[str, Any]]:
    with neo4j_driver.session() as session:
        cypher = """
            MATCH (m:Method)
            MATCH (aw:ActiveWorkspace)-[:ACTIVE_REVISION]->(wr:WorkspaceRevision)
            WHERE m.method_key = $method_key
              AND aw.workspace_id = m.workspace_id
              AND wr.workspace_id = m.workspace_id
              AND wr.revision_id = m.revision_id
              AND wr.schema_version = 'codegraph-jdt/v1'
            MATCH path=(m)-[:CALLS|DECLARES|NESTED_IN*1..2]-(n)
            RETURN m.signature AS method,
                   collect(DISTINCT CASE
                     WHEN n:Method THEN {type: 'Method', id: n.method_key, display: n.signature}
                     WHEN n:Class  THEN {type: 'Class',  id: n.type_key, display: n.fqn}
                     ELSE {type: 'Node', id: n.call_key, display: n.name}
                   END) AS neighbors
            """
        result = session.run(cypher, method_key=method_key)
        return [record.data() if hasattr(record, "data") else dict(record) for record in result]
