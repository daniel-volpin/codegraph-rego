"""
Hybrid search internals: cached loaders, semantic search over FAISS, and
graph context retrieval via Neo4j. Extracted from hybrid_code_search to
reduce coupling with scripts and enable reuse from services and API.
"""

from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from neo4j import Driver

from codegraph.config import settings
from codegraph.search.artifacts import ActiveEmbeddingGeneration, ArtifactConsistencyError, load_active_generation

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


@dataclass(frozen=True)
class SearchArtifactsBundle:
    index: Any
    signature_map: list[str]
    generation: ActiveEmbeddingGeneration | None
    index_identity: tuple[str, int, int]
    signature_map_identity: tuple[str, int, int]


def _path_identity(path: Path) -> tuple[str, int, int]:
    stat = path.stat()
    return (str(path), stat.st_mtime_ns, stat.st_size)


def _safe_setting(name: str, default: str | None = None) -> str | None:
    return getattr(settings, name, default)


def _is_configured_index_path(path: Path) -> bool:
    configured = _safe_setting("faiss_index_path")
    return configured is not None and path == Path(configured).resolve()


def _is_configured_map_path(path: Path) -> bool:
    configured_full = _safe_setting("signature_map_path_full")
    configured_legacy = _safe_setting("signature_map_path")
    configured_paths = [value for value in (configured_full, configured_legacy) if value is not None]
    return any(path == Path(value).resolve() for value in configured_paths)


def _resolve_active_generation(*, required: bool) -> ActiveEmbeddingGeneration | None:
    if not required:
        return None
    manifest_path = _safe_setting("embedding_metadata_path")
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
            "Managed embedding artifacts are inconsistent. Legacy mixed index/map loading is disabled. "
            f"Rebuild embeddings to republish a complete generation. Details: {exc}"
        ) from exc


def _legacy_load_signature_map(path: Path) -> list[str]:
    with path.open(encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, list) or any(not isinstance(value, str) or not value for value in payload):
        raise ValueError(f"Invalid signature map at {path}: expected a list of method identifiers")
    return payload


def _read_faiss_index(path: Path):
    import faiss

    return faiss.read_index(str(path))


def _load_bundle_locked(index_path: str | None, signature_map_path: str | None) -> SearchArtifactsBundle:
    global _INDEX, _INDEX_MTIME, _SIGMAP, _SIGMAP_MTIME
    requested_index_path = Path(index_path or settings.faiss_index_path).resolve()
    requested_map_path = Path(signature_map_path or settings.signature_map_path_full).resolve()
    managed_request = (
        (index_path is None or _is_configured_index_path(requested_index_path))
        and (signature_map_path is None or _is_configured_map_path(requested_map_path))
    )
    generation = _resolve_active_generation(required=managed_request)
    resolved_index_path = generation.index_path if generation is not None else requested_index_path
    resolved_map_path = generation.signature_map_path if generation is not None else requested_map_path
    if not resolved_map_path.is_file():
        raise FileNotFoundError(f"Signature map not found at {resolved_map_path}")
    index_identity = _path_identity(resolved_index_path)
    map_identity = _path_identity(resolved_map_path)

    index = _INDEX if _INDEX is not None and _INDEX_MTIME == index_identity else _read_faiss_index(resolved_index_path)
    signature_map = (
        _SIGMAP if _SIGMAP is not None and _SIGMAP_MTIME == map_identity else _legacy_load_signature_map(resolved_map_path)
    )
    if index.ntotal != len(signature_map):
        raise ValueError("FAISS index and signature map have different method counts")
    if generation is not None:
        if index.ntotal != generation.count:
            raise ValueError(
                f"Active generation {generation.generation_id} count mismatch: "
                f"manifest count={generation.count}, index ntotal={index.ntotal}"
            )
        if generation.dim is not None and hasattr(index, "d") and int(index.d) != generation.dim:
            raise ValueError(
                f"Active generation {generation.generation_id} dimension mismatch: "
                f"manifest dim={generation.dim}, index dim={int(index.d)}"
            )
    _INDEX = index
    _INDEX_MTIME = index_identity
    _SIGMAP = signature_map
    _SIGMAP_MTIME = map_identity
    return SearchArtifactsBundle(
        index=index,
        signature_map=signature_map,
        generation=generation,
        index_identity=index_identity,
        signature_map_identity=map_identity,
    )


def load_search_artifacts_bundle(
    *,
    index_path: str | None = None,
    signature_map_path: str | None = None,
) -> SearchArtifactsBundle:
    with _ARTIFACT_LOCK:
        return _load_bundle_locked(index_path=index_path, signature_map_path=signature_map_path)


def load_faiss_index(index_path: str | None = None):
    global _INDEX, _INDEX_MTIME
    requested_path = Path(index_path or settings.faiss_index_path).resolve()
    managed_request = index_path is None or _is_configured_index_path(requested_path)
    with _ARTIFACT_LOCK:
        generation = _resolve_active_generation(required=managed_request)
        resolved_path = generation.index_path if generation is not None else requested_path
        identity = _path_identity(resolved_path)
        if _INDEX is not None and _INDEX_MTIME == identity:
            return _INDEX
        index = _read_faiss_index(resolved_path)
        if generation is not None:
            if index.ntotal != generation.count:
                raise ValueError(
                    f"Active generation {generation.generation_id} count mismatch: "
                    f"manifest count={generation.count}, index ntotal={index.ntotal}"
                )
            if generation.dim is not None and hasattr(index, "d") and int(index.d) != generation.dim:
                raise ValueError(
                    f"Active generation {generation.generation_id} dimension mismatch: "
                    f"manifest dim={generation.dim}, index dim={int(index.d)}"
                )
        _INDEX = index
        _INDEX_MTIME = identity
        return _INDEX


def load_signature_map(map_path: str | None = None) -> list[str]:
    global _SIGMAP, _SIGMAP_MTIME
    candidates = [map_path] if map_path is not None else [settings.signature_map_path_full, settings.signature_map_path]
    for candidate in candidates:
        path = Path(candidate).resolve()
        with _ARTIFACT_LOCK:
            managed_request = map_path is None or _is_configured_map_path(path)
            generation = _resolve_active_generation(required=managed_request)
            resolved_path = generation.signature_map_path if generation is not None else path
            if not resolved_path.is_file():
                continue
            identity = _path_identity(resolved_path)
            if _SIGMAP is not None and _SIGMAP_MTIME == identity:
                return _SIGMAP
            payload = _legacy_load_signature_map(resolved_path)
            if generation is not None and len(payload) != generation.count:
                raise ValueError(
                    f"Active generation {generation.generation_id} signature map count mismatch: "
                    f"manifest count={generation.count}, map entries={len(payload)}"
                )
            _SIGMAP = payload
            _SIGMAP_MTIME = identity
            return payload
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
