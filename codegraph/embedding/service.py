from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from neo4j import GraphDatabase

from codegraph.config import settings

if TYPE_CHECKING:
    import numpy as np
    from sentence_transformers import SentenceTransformer

CONTEXT_LINES_BEFORE = 5
CONTEXT_LINES_AFTER = 20
LOGGER = logging.getLogger(__name__)
ProgressCallback = Callable[[str, str, float], None]
EmbeddingCache = dict[str, dict[str, object]]


@dataclass(frozen=True)
class _MethodSnippet:
    signature: str
    code: str


@dataclass(frozen=True)
class _EmbeddingPlan:
    vectors_by_sig: dict[str, list[float]]
    snippets_to_encode: list[str]
    signatures_to_encode: list[str]
    hashes_to_encode: list[str]
    cached_hits: int


def _hash_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _load_embedding_cache(cache_path: str, model_name: str) -> EmbeddingCache:
    path = Path(cache_path)
    if not path.is_file():
        return {}
    try:
        with path.open(encoding="utf-8") as handle:
            payload = json.load(handle) or {}
    except json.JSONDecodeError:
        LOGGER.warning("Embedding cache at %s is invalid JSON; ignoring.", cache_path)
        return {}
    if payload.get("model") != model_name:
        LOGGER.info("Embedding cache model mismatch; ignoring cached vectors.")
        return {}
    entries = payload.get("entries")
    if isinstance(entries, dict):
        return entries
    return {}


def _persist_embedding_cache(
    cache_path: str,
    model_name: str,
    dim: int | None,
    entries: EmbeddingCache,
) -> None:
    payload = {
        "model": model_name,
        "dim": dim,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "entries": entries,
    }
    path = Path(cache_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle)


def _write_json(path: str | Path, payload: Any, *, indent: int | None = None) -> None:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=indent)


def _cache_vector_dim(cache_entries: EmbeddingCache) -> int | None:
    sample = next(iter(cache_entries.values()), None)
    if not isinstance(sample, dict):
        return None
    vector = sample.get("vector")
    return len(vector) if isinstance(vector, list) else None


def _fetch_method_snippets() -> list[_MethodSnippet]:
    snippets: list[_MethodSnippet] = []
    query = "MATCH (m:Method) RETURN coalesce(m.full_signature, m.signature) AS sig, m.name AS name, m.file_path AS path"
    with GraphDatabase.driver(settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_pass)) as driver:
        with driver.session() as session:
            for record in session.run(query):
                code = EmbeddingService.extract_method_snippet(record["path"], record["name"])
                if code:
                    snippets.append(_MethodSnippet(signature=record["sig"], code=code))
    return snippets


def _plan_embedding_work(
    method_snippets: list[_MethodSnippet],
    cache_entries: EmbeddingCache,
    *,
    rebuild_index: bool,
) -> _EmbeddingPlan:
    cache_dim = _cache_vector_dim(cache_entries)
    vectors_by_sig: dict[str, list[float]] = {}
    snippets_to_encode: list[str] = []
    signatures_to_encode: list[str] = []
    hashes_to_encode: list[str] = []
    cached_hits = 0

    for snippet in method_snippets:
        code_hash = _hash_text(snippet.code)
        cached = cache_entries.get(snippet.signature) if cache_entries else None
        vector = cached.get("vector") if isinstance(cached, dict) else None
        cached_hash = cached.get("hash") if isinstance(cached, dict) else None
        if _cache_hit(vector, cached_hash, code_hash, cache_dim=cache_dim, rebuild_index=rebuild_index):
            vectors_by_sig[snippet.signature] = list(vector) if isinstance(vector, list) else []
            cached_hits += 1
            continue
        snippets_to_encode.append(snippet.code)
        signatures_to_encode.append(snippet.signature)
        hashes_to_encode.append(code_hash)

    return _EmbeddingPlan(
        vectors_by_sig=vectors_by_sig,
        snippets_to_encode=snippets_to_encode,
        signatures_to_encode=signatures_to_encode,
        hashes_to_encode=hashes_to_encode,
        cached_hits=cached_hits,
    )


def _cache_hit(
    vector: object,
    cached_hash: object,
    code_hash: str,
    *,
    cache_dim: int | None,
    rebuild_index: bool,
) -> bool:
    return (
        not rebuild_index
        and isinstance(vector, list)
        and cached_hash == code_hash
        and (cache_dim is None or len(vector) == cache_dim)
    )


def _encode_missing_vectors(
    model: SentenceTransformer,
    plan: _EmbeddingPlan,
    cache_entries: EmbeddingCache,
) -> dict[str, list[float]]:
    if not plan.snippets_to_encode:
        return {}

    encoded = model.encode(plan.snippets_to_encode, normalize_embeddings=True)
    vectors: dict[str, list[float]] = {}
    for idx, signature in enumerate(plan.signatures_to_encode):
        vector = encoded[idx].tolist()
        vectors[signature] = vector
        cache_entries[signature] = {"hash": plan.hashes_to_encode[idx], "vector": vector}
    return vectors


def _build_faiss_index(vectors_np: np.ndarray, index_path: Path) -> int | None:
    import faiss

    if vectors_np.ndim != 2 or vectors_np.shape[0] == 0:
        return None
    dim = int(vectors_np.shape[1])
    index = faiss.IndexFlatIP(dim)
    index.add(vectors_np)
    faiss.write_index(index, str(index_path))
    return dim


class EmbeddingService:
    """
    Service for building code embeddings and FAISS index for semantic code search.
    """

    @staticmethod
    def extract_method_snippet(file_path: str, method_name: str) -> str:
        from codegraph.common.snippet_utils import extract_code_snippet

        return extract_code_snippet(file_path, method_name, before=CONTEXT_LINES_BEFORE, after=CONTEXT_LINES_AFTER)

    @staticmethod
    def build_embeddings(
        progress_callback: ProgressCallback | None = None,
        *,
        rebuild_index: bool = False,
    ) -> None:
        """
        Main workflow:
        1. Query Neo4j for all methods, retrieving their signature, name, and file path.
        2. For each method, extract a code snippet from the source file.
        3. Generate embeddings for all extracted code snippets using SentenceTransformer.
        4. Build a FAISS index for fast vector search and save it to disk.
        5. Save the mapping from FAISS index to method signatures as a JSON file.
        """
        import numpy as np

        if progress_callback:
            progress_callback("embedding", "Fetching methods from Neo4j…", 82.0)
        method_snippets = _fetch_method_snippets()
        signatures = [snippet.signature for snippet in method_snippets]
        if not signatures:
            LOGGER.warning("No method snippets found; skipping embedding build.")
            return

        cache_entries: EmbeddingCache = (
            {} if rebuild_index else _load_embedding_cache(settings.embedding_cache_path, settings.embedding_model_name)
        )
        if progress_callback:
            progress_callback("embedding", f"Preparing {len(signatures)} methods…", 84.0)
        plan = _plan_embedding_work(method_snippets, cache_entries, rebuild_index=rebuild_index)

        vectors_by_sig = dict(plan.vectors_by_sig)
        if plan.snippets_to_encode:
            from sentence_transformers import SentenceTransformer

            if progress_callback:
                progress_callback("embedding", f"Encoding {len(plan.snippets_to_encode)} methods…", 86.0)
            model = SentenceTransformer(settings.embedding_model_name)
            vectors_by_sig.update(_encode_missing_vectors(model, plan, cache_entries))
        elif progress_callback:
            progress_callback("embedding", "All embeddings reused from cache.", 86.0)

        vectors_list = [vectors_by_sig[sig] for sig in signatures if sig in vectors_by_sig]
        vectors_np = np.asarray(vectors_list, dtype="float32")
        LOGGER.info("Embedding %d methods", len(signatures))
        if progress_callback:
            progress_callback(
                "embedding",
                f"Cache hits: {plan.cached_hits}; encoded: {len(plan.snippets_to_encode)}",
                88.0,
            )
        LOGGER.info("Embedding tensor prepared with shape=%s dtype=%s", vectors_np.shape, vectors_np.dtype)

        index_dir = Path(settings.index_dir)
        index_dir.mkdir(parents=True, exist_ok=True)
        index_path = index_dir / "code_embeddings.index"
        sigmap_legacy_path = index_dir / "embedding_signature_map.json"
        sigmap_full_path = index_dir / "embedding_full_signature_map.json"
        dim = _build_faiss_index(vectors_np, index_path)
        if dim is not None and progress_callback:
            progress_callback("embedding", "FAISS index written to disk.", 92.0)

        _write_json(sigmap_full_path, signatures)
        _write_json(sigmap_legacy_path, signatures)
        if progress_callback:
            progress_callback("embedding", "Embedding metadata saved.", 95.0)
        metadata = {
            "model": settings.embedding_model_name,
            "dim": dim,
            "metric": "cosine",
            "count": len(signatures),
            "built_at": datetime.now(timezone.utc).isoformat(),
            "index_path": str(index_path),
            "signature_map": {"full": str(sigmap_full_path), "legacy": str(sigmap_legacy_path)},
            "cache_path": settings.embedding_cache_path,
            "cache_hits": plan.cached_hits,
            "cache_misses": len(plan.snippets_to_encode),
        }
        _write_json(settings.embedding_metadata_path, metadata, indent=2)
        try:
            _persist_embedding_cache(settings.embedding_cache_path, settings.embedding_model_name, dim, cache_entries)
        except Exception as exc:
            LOGGER.warning("Failed to persist embedding cache: %s", exc)
        LOGGER.info("Saved FAISS index to %s and signature map to %s", index_path, sigmap_full_path)
        if progress_callback:
            progress_callback("embedding", "Embedding build complete.", 98.0)
