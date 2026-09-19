from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from codegraph.search.artifacts import canonical_graph_generation, sha256_file

if TYPE_CHECKING:
    import numpy as np
    from sentence_transformers import SentenceTransformer

LOGGER = logging.getLogger(__name__)
ProgressCallback = Callable[[str, str, float], None]
EmbeddingCache = dict[str, dict[str, object]]


@dataclass(frozen=True)
class MethodSnippet:
    method_key: str
    display_signature: str
    code: str


@dataclass(frozen=True)
class EmbeddingPlan:
    vectors_by_sig: dict[str, list[float]]
    snippets_to_encode: list[str]
    signatures_to_encode: list[str]
    hashes_to_encode: list[str]
    cached_hits: int


def hash_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def load_embedding_cache(cache_path: str, model_name: str) -> EmbeddingCache:
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


def persist_embedding_cache(
    cache_path: str,
    model_name: str,
    dim: int | None,
    entries: EmbeddingCache,
) -> None:
    payload = {
        "model": model_name,
        "dim": dim,
        "updated_at": datetime.now(UTC).isoformat(),
        "entries": entries,
    }
    path = Path(cache_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle)


def write_json(path: str | Path, payload: Any, *, indent: int | None = None) -> None:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=indent)


def atomic_write_json(path: Path, payload: Any, *, indent: int | None = None) -> None:
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


def publish_generation_manifest(
    *,
    manifest_path: Path,
    generation_id: str,
    model_name: str,
    dim: int | None,
    count: int,
    index_path: Path,
    signature_map_path: Path,
    metadata_path: Path,
    graph_generation: dict[str, Any] | None = None,
) -> None:
    manifest = {
        "schema": "embedding_generation_manifest.v1",
        "switched_at": datetime.now(UTC).isoformat(),
        "generation": {
            "id": generation_id,
            "model": model_name,
            "dim": dim,
            "count": count,
            "graph_generation": graph_generation,
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
    atomic_write_json(manifest_path, manifest, indent=2)


def canonical_graph_generation_helper(value: dict[str, Any] | None) -> dict[str, Any]:
    return canonical_graph_generation(value)


def cache_vector_dim(cache_entries: EmbeddingCache) -> int | None:
    sample = next(iter(cache_entries.values()), None)
    if not isinstance(sample, dict):
        return None
    vector = sample.get("vector")
    return len(vector) if isinstance(vector, list) else None


def cache_hit(
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


def plan_embedding_work(
    method_snippets: list[MethodSnippet],
    cache_entries: EmbeddingCache,
    *,
    rebuild_index: bool,
) -> EmbeddingPlan:
    dim = cache_vector_dim(cache_entries)
    vectors_by_sig: dict[str, list[float]] = {}
    snippets_to_encode: list[str] = []
    signatures_to_encode: list[str] = []
    hashes_to_encode: list[str] = []
    cached_hits = 0

    for snippet in method_snippets:
        code_hash = hash_text(snippet.code)
        cached = cache_entries.get(snippet.method_key) if cache_entries else None
        vector = cached.get("vector") if isinstance(cached, dict) else None
        cached_hash = cached.get("hash") if isinstance(cached, dict) else None
        if cache_hit(vector, cached_hash, code_hash, cache_dim=dim, rebuild_index=rebuild_index):
            vectors_by_sig[snippet.method_key] = list(vector) if isinstance(vector, list) else []
            cached_hits += 1
            continue
        snippets_to_encode.append(snippet.code)
        signatures_to_encode.append(snippet.method_key)
        hashes_to_encode.append(code_hash)

    return EmbeddingPlan(
        vectors_by_sig=vectors_by_sig,
        snippets_to_encode=snippets_to_encode,
        signatures_to_encode=signatures_to_encode,
        hashes_to_encode=hashes_to_encode,
        cached_hits=cached_hits,
    )


def encode_missing_vectors(
    model: SentenceTransformer,
    plan: EmbeddingPlan,
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


def build_faiss_index(vectors_np: np.ndarray, index_path: Path) -> int | None:
    import faiss  # noqa: PLC0415

    if vectors_np.ndim != 2 or vectors_np.shape[0] == 0:
        return None
    dim = int(vectors_np.shape[1])
    index = faiss.IndexFlatIP(dim)
    index.add(vectors_np)
    faiss.write_index(index, str(index_path))
    return dim
