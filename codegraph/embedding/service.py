from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from neo4j import GraphDatabase

from codegraph.config import settings
from codegraph.search.artifacts import sha256_file

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


def _atomic_write_json(path: Path, payload: Any, *, indent: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.tmp-",
        delete=False,
    ) as handle:
        tmp_path = Path(handle.name)
    try:
        with tmp_path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=indent)
        os.replace(tmp_path, path)
    finally:
        if tmp_path is not None and tmp_path.exists():
            tmp_path.unlink()


def _publish_generation_manifest(
    *,
    manifest_path: Path,
    generation_id: str,
    model_name: str,
    dim: int | None,
    count: int,
    index_path: Path,
    signature_map_path: Path,
    metadata_path: Path,
) -> None:
    manifest = {
        "schema": "embedding_generation_manifest.v1",
        "switched_at": datetime.now(timezone.utc).isoformat(),
        "generation": {
            "id": generation_id,
            "model": model_name,
            "dim": dim,
            "count": count,
            "metadata": {
                "index_path": str(index_path),
                "index_sha256": sha256_file(index_path),
                "signature_map_path": str(signature_map_path),
                "signature_map_sha256": sha256_file(signature_map_path),
                "metadata_path": str(metadata_path),
                "metadata_sha256": sha256_file(metadata_path),
            },
        },
    }
    _atomic_write_json(manifest_path, manifest, indent=2)


def _cache_vector_dim(cache_entries: EmbeddingCache) -> int | None:
    sample = next(iter(cache_entries.values()), None)
    if not isinstance(sample, dict):
        return None
    vector = sample.get("vector")
    return len(vector) if isinstance(vector, list) else None


def _fetch_method_snippets() -> list[_MethodSnippet]:
    from codegraph.common.snippet_utils import extract_snippet_by_lines

    snippets: list[_MethodSnippet] = []
    query = (
        "MATCH (m:Method) "
        "RETURN coalesce(m.full_signature, m.signature) AS sig, "
        "m.name AS name, m.file_path AS path, m.start_line AS start_line, m.end_line AS end_line"
    )
    with GraphDatabase.driver(settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_pass)) as driver:
        with driver.session() as session:
            for record in session.run(query):
                path = record["path"]
                name = record["name"]
                signature = record["sig"]
                start_line = record.get("start_line")
                end_line = record.get("end_line")
                code = ""
                has_no_range = start_line is None and end_line is None
                has_complete_range = isinstance(start_line, int) and isinstance(end_line, int)
                if has_complete_range:
                    code = extract_snippet_by_lines(path, start_line, end_line, padding=0, strict_range=True)
                    if not code:
                        LOGGER.warning(
                            "Skipping method snippet for signature %s: invalid source range %s-%s in %s",
                            signature,
                            start_line,
                            end_line,
                            path,
                        )
                elif has_no_range:
                    code = EmbeddingService.extract_method_snippet(path, name)
                    if not code:
                        LOGGER.warning(
                            "Skipping method snippet for signature %s: missing or ambiguous range fallback in %s",
                            signature,
                            path,
                        )
                else:
                    LOGGER.warning(
                        "Skipping method snippet for signature %s: incomplete source range metadata start=%r end=%r in %s",
                        signature,
                        start_line,
                        end_line,
                        path,
                    )
                if code:
                    snippets.append(_MethodSnippet(signature=signature, code=code))
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
        generation_id = uuid.uuid4().hex
        index_path = index_dir / f"code_embeddings.{generation_id}.index"
        sigmap_full_path = index_dir / f"embedding_full_signature_map.{generation_id}.json"
        metadata_path = index_dir / f"embedding_metadata.{generation_id}.json"
        if len(vectors_list) != len(signatures):
            raise RuntimeError(
                f"Refusing to publish embedding artifacts: vector/signature count mismatch "
                f"({len(vectors_list)} vectors for {len(signatures)} signatures)"
            )
        dim = _build_faiss_index(vectors_np, index_path)
        if dim is not None and progress_callback:
            progress_callback("embedding", "FAISS index written to disk.", 92.0)
        if vectors_np.shape[0] != len(signatures):
            raise RuntimeError(
                f"Refusing to publish embedding artifacts: FAISS index input count mismatch "
                f"({vectors_np.shape[0]} vectors for {len(signatures)} signatures)"
            )

        _write_json(sigmap_full_path, signatures)
        if progress_callback:
            progress_callback("embedding", "Embedding metadata saved.", 95.0)
        metadata = {
            "model": settings.embedding_model_name,
            "dim": dim,
            "metric": "cosine",
            "count": len(signatures),
            "built_at": datetime.now(timezone.utc).isoformat(),
            "index_path": str(index_path),
            "signature_map": {"full": str(sigmap_full_path)},
            "cache_path": settings.embedding_cache_path,
            "cache_hits": plan.cached_hits,
            "cache_misses": len(plan.snippets_to_encode),
        }
        _write_json(metadata_path, metadata, indent=2)
        if dim is None:
            raise RuntimeError("Refusing to publish embedding artifacts: FAISS index is empty")
        _publish_generation_manifest(
            manifest_path=Path(settings.embedding_metadata_path),
            generation_id=generation_id,
            model_name=settings.embedding_model_name,
            dim=dim,
            count=len(signatures),
            index_path=index_path,
            signature_map_path=sigmap_full_path,
            metadata_path=metadata_path,
        )
        try:
            _persist_embedding_cache(settings.embedding_cache_path, settings.embedding_model_name, dim, cache_entries)
        except Exception as exc:
            LOGGER.warning("Failed to persist embedding cache: %s", exc)
        LOGGER.info("Saved FAISS index to %s and signature map to %s", index_path, sigmap_full_path)
        if progress_callback:
            progress_callback("embedding", "Embedding build complete.", 98.0)
