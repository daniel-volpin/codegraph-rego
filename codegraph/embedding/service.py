import hashlib
import json
import logging
import os
from collections.abc import Callable
from datetime import datetime, timezone

import faiss
import numpy as np
from neo4j import GraphDatabase
from sentence_transformers import SentenceTransformer

from codegraph.config import settings

CONTEXT_LINES_BEFORE = 5
CONTEXT_LINES_AFTER = 20
LOGGER = logging.getLogger(__name__)


def _hash_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _load_embedding_cache(cache_path: str, model_name: str) -> dict[str, dict[str, object]]:
    if not os.path.isfile(cache_path):
        return {}
    try:
        with open(cache_path) as handle:
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
    entries: dict[str, dict[str, object]],
) -> None:
    payload = {
        "model": model_name,
        "dim": dim,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "entries": entries,
    }
    os.makedirs(os.path.dirname(cache_path) or ".", exist_ok=True)
    with open(cache_path, "w") as handle:
        json.dump(payload, handle)


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
        progress_callback: Callable[[str, str, float], None] | None = None,
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
        method_records: list[tuple[str, str]] = []
        if progress_callback:
            progress_callback("embedding", "Fetching methods from Neo4j…", 82.0)
        model = SentenceTransformer(settings.embedding_model_name)
        with GraphDatabase.driver(settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_pass)) as driver:
            with driver.session() as session:
                results = session.run(
                    "MATCH (m:Method) RETURN coalesce(m.full_signature, m.signature) AS sig, m.name AS name, m.file_path AS path"
                )
                for record in results:
                    code = EmbeddingService.extract_method_snippet(record["path"], record["name"])
                    if code:
                        method_records.append((record["sig"], code))
        signatures = [sig for sig, _ in method_records]
        if rebuild_index:
            cache_entries: dict[str, dict[str, object]] = {}
        else:
            cache_entries = _load_embedding_cache(settings.embedding_cache_path, settings.embedding_model_name)
        if not signatures:
            LOGGER.warning("No method snippets found; skipping embedding build.")
            return
        if progress_callback:
            progress_callback("embedding", f"Preparing {len(signatures)} methods…", 84.0)
        cached_hits = 0
        to_encode: list[str] = []
        to_encode_sigs: list[str] = []
        to_encode_hashes: list[str] = []
        vectors_by_sig: dict[str, list[float]] = {}
        cache_dim = None
        if cache_entries:
            sample = next(iter(cache_entries.values()), None)
            if isinstance(sample, dict):
                cached_vector = sample.get("vector")
                if isinstance(cached_vector, list):
                    cache_dim = len(cached_vector)
        for sig, code in method_records:
            code_hash = _hash_text(code)
            cached = cache_entries.get(sig) if cache_entries else None
            vector = cached.get("vector") if isinstance(cached, dict) else None
            cached_hash = cached.get("hash") if isinstance(cached, dict) else None
            if (
                not rebuild_index
                and isinstance(vector, list)
                and cached_hash == code_hash
                and (cache_dim is None or len(vector) == cache_dim)
            ):
                vectors_by_sig[sig] = vector
                cached_hits += 1
                continue
            to_encode.append(code)
            to_encode_sigs.append(sig)
            to_encode_hashes.append(code_hash)
        if to_encode:
            if progress_callback:
                progress_callback("embedding", f"Encoding {len(to_encode)} methods…", 86.0)
            encoded = model.encode(to_encode, normalize_embeddings=True)
            for idx, sig in enumerate(to_encode_sigs):
                vec = encoded[idx].tolist()
                vectors_by_sig[sig] = vec
                cache_entries[sig] = {"hash": to_encode_hashes[idx], "vector": vec}
        else:
            if progress_callback:
                progress_callback("embedding", "All embeddings reused from cache.", 86.0)
        vectors_list = [vectors_by_sig[sig] for sig in signatures if sig in vectors_by_sig]
        vectors_np = np.asarray(vectors_list, dtype="float32")
        LOGGER.info("Embedding %d methods", len(signatures))
        if progress_callback:
            progress_callback("embedding", f"Cache hits: {cached_hits}; encoded: {len(to_encode)}", 88.0)
        LOGGER.info("Embedding tensor prepared with shape=%s dtype=%s", vectors_np.shape, vectors_np.dtype)
        os.makedirs(settings.index_dir, exist_ok=True)
        index_path = os.path.join(settings.index_dir, "code_embeddings.index")
        sigmap_legacy_path = os.path.join(settings.index_dir, "embedding_signature_map.json")
        sigmap_full_path = os.path.join(settings.index_dir, "embedding_full_signature_map.json")
        if vectors_np.shape[0] > 0:
            dim = int(vectors_np.shape[1])
            index = faiss.IndexFlatIP(dim)
            # Ensure vectors_np is 2D and non-empty before adding
            if vectors_np.ndim == 2 and vectors_np.shape[0] > 0:
                index.add(vectors_np)
                faiss.write_index(index, index_path)
                if progress_callback:
                    progress_callback("embedding", "FAISS index written to disk.", 92.0)
        else:
            # No vectors: do not create or save index
            index = None
            dim = None
        with open(sigmap_full_path, "w") as f:
            json.dump(signatures, f)
        try:
            with open(sigmap_legacy_path, "w") as f:
                json.dump(signatures, f)
        except Exception:
            pass
        if progress_callback:
            progress_callback("embedding", "Embedding metadata saved.", 95.0)
        metadata = {
            "model": settings.embedding_model_name,
            "dim": dim,
            "metric": "cosine",
            "count": len(signatures),
            "built_at": datetime.now(timezone.utc).isoformat(),
            "index_path": index_path,
            "signature_map": {"full": sigmap_full_path, "legacy": sigmap_legacy_path},
            "cache_path": settings.embedding_cache_path,
            "cache_hits": cached_hits,
            "cache_misses": len(to_encode),
        }
        try:
            with open(settings.embedding_metadata_path, "w") as f:
                json.dump(metadata, f, indent=2)
        except Exception:
            pass
        try:
            _persist_embedding_cache(settings.embedding_cache_path, settings.embedding_model_name, dim, cache_entries)
        except Exception as exc:
            LOGGER.warning("Failed to persist embedding cache: %s", exc)
        LOGGER.info("Saved FAISS index to %s and signature map to %s", index_path, sigmap_full_path)
        if progress_callback:
            progress_callback("embedding", "Embedding build complete.", 98.0)
