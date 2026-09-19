from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from neo4j import GraphDatabase

from codegraph.config import settings
from codegraph.embedding.service_helpers import (
    EmbeddingCache,
)
from codegraph.embedding.service_helpers import (
    MethodSnippet as _MethodSnippet,
)
from codegraph.embedding.service_helpers import (
    build_faiss_index as _build_faiss_index,
)
from codegraph.embedding.service_helpers import (
    canonical_graph_generation_helper as _canonical_graph_generation,
)
from codegraph.embedding.service_helpers import (
    encode_missing_vectors as _encode_missing_vectors,
)
from codegraph.embedding.service_helpers import (
    load_embedding_cache as _load_embedding_cache,
)
from codegraph.embedding.service_helpers import (
    persist_embedding_cache as _persist_embedding_cache,
)
from codegraph.embedding.service_helpers import (
    plan_embedding_work as _plan_embedding_work,
)
from codegraph.embedding.service_helpers import (
    publish_generation_manifest as _publish_generation_manifest,
)
from codegraph.embedding.service_helpers import (
    write_json as _write_json,
)
from codegraph.policy.runtime.bundles import validate_graph_generation

if TYPE_CHECKING:
    pass

CONTEXT_LINES_BEFORE = 5
CONTEXT_LINES_AFTER = 20
LOGGER = logging.getLogger(__name__)
ProgressCallback = Callable[[str, str, float], None]


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



def _fetch_method_snippets() -> list[_MethodSnippet]:
    snippets: list[_MethodSnippet] = []
    query = (
        "MATCH (m:Method) "
        "MATCH (aw:ActiveWorkspace)-[:ACTIVE_REVISION]->(wr:WorkspaceRevision) "
        "WHERE m.method_key IS NOT NULL "
        "AND aw.workspace_id = m.workspace_id "
        "AND wr.workspace_id = m.workspace_id "
        "AND wr.revision_id = m.revision_id "
        "AND wr.schema_version = 'codegraph-jdt/v1' "
        "AND m.range_status = 'verified' "
        "AND m.start_byte IS NOT NULL "
        "AND m.end_byte IS NOT NULL "
        "RETURN m.method_key AS method_key, "
        "m.signature AS display_signature, "
        "m.file_path AS path, m.start_byte AS start_byte, m.end_byte AS end_byte, "
        "m.source_sha256 AS source_sha256"
    )
    with GraphDatabase.driver(settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_pass)) as driver:
        with driver.session() as session:
            for record in session.run(query):
                path = record["path"]
                method_key = record["method_key"]
                display_signature = record["display_signature"]
                start_byte = record.get("start_byte")
                end_byte = record.get("end_byte")
                has_complete_range = isinstance(start_byte, int) and isinstance(end_byte, int)
                if not has_complete_range:
                    raise RuntimeError(
                        "Refusing to publish embedding artifacts: indexable method "
                        f"{method_key} has incomplete byte range metadata start={start_byte!r} end={end_byte!r}"
                    )
                raw = Path(path).read_bytes()
                expected_sha = record.get("source_sha256")
                if isinstance(expected_sha, str) and expected_sha:
                    actual_sha = hashlib.sha256(raw).hexdigest()
                    if actual_sha != expected_sha:
                        raise RuntimeError(
                            "Refusing to publish embedding artifacts: source hash mismatch for "
                            f"method key {method_key} in {path}"
                        )
                if end_byte < start_byte or end_byte > len(raw):
                    raise RuntimeError(
                        "Refusing to publish embedding artifacts: invalid byte range "
                        f"{start_byte}-{end_byte} for method key {method_key} in {path}"
                    )
                try:
                    code = raw[start_byte:end_byte].decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise RuntimeError(
                        "Refusing to publish embedding artifacts: source range is not UTF-8 for "
                        f"method key {method_key} in {path}"
                    ) from exc
                if not code:
                    raise RuntimeError(
                        "Refusing to publish embedding artifacts: empty source range "
                        f"{start_byte}-{end_byte} for method key {method_key} in {path}"
                    )
                snippets.append(_MethodSnippet(method_key=method_key, display_signature=display_signature, code=code))
    return snippets


def _fetch_active_graph_generation() -> dict[str, Any]:
    with GraphDatabase.driver(settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_pass)) as driver:
        return validate_graph_generation(driver)


class EmbeddingService:
    """
    Service for building code embeddings and FAISS index for semantic code search.
    """

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
        import numpy as np  # noqa: PLC0415 - lazy-loads a heavy native/ML dependency

        if progress_callback:
            progress_callback("embedding", "Fetching methods from Neo4j…", 82.0)
        graph_generation = _fetch_active_graph_generation()
        method_snippets = _fetch_method_snippets()
        signatures = [snippet.method_key for snippet in method_snippets]
        indexable_method_count = int(graph_generation.get("indexable_method_count") or 0)
        if len(signatures) != indexable_method_count:
            raise RuntimeError(
                f"Refusing to publish embedding artifacts: indexed snippet count does not match "
                f"active graph indexable method count ({len(signatures)} snippets for {indexable_method_count} "
                "indexable methods)"
            )
        if not signatures:
            raise RuntimeError("No indexable source methods found; cannot publish a search generation.")

        cache_entries: EmbeddingCache = (
            {} if rebuild_index else _load_embedding_cache(settings.embedding_cache_path, settings.embedding_model_name)
        )
        if progress_callback:
            progress_callback("embedding", f"Preparing {len(signatures)} methods…", 84.0)
        plan = _plan_embedding_work(method_snippets, cache_entries, rebuild_index=rebuild_index)

        vectors_by_sig = dict(plan.vectors_by_sig)
        if plan.snippets_to_encode:
            from sentence_transformers import (
                SentenceTransformer,  # noqa: PLC0415 - lazy-loads a heavy native/ML dependency
            )

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
            "built_at": datetime.now(UTC).isoformat(),
            "index_path": str(index_path),
            "signature_map": {"full": str(sigmap_full_path)},
            "cache_path": settings.embedding_cache_path,
            "cache_hits": plan.cached_hits,
            "cache_misses": len(plan.snippets_to_encode),
        }
        _write_json(metadata_path, metadata, indent=2)
        if dim is None:
            raise RuntimeError("Refusing to publish embedding artifacts: FAISS index is empty")
        latest_graph_generation = _fetch_active_graph_generation()
        if _canonical_graph_generation(latest_graph_generation) != _canonical_graph_generation(graph_generation):
            raise RuntimeError("Refusing to publish embedding artifacts: active graph generation changed during build.")
        _publish_generation_manifest(
            manifest_path=Path(settings.embedding_metadata_path),
            generation_id=generation_id,
            model_name=settings.embedding_model_name,
            dim=dim,
            count=len(signatures),
            index_path=index_path,
            signature_map_path=sigmap_full_path,
            metadata_path=metadata_path,
            graph_generation=latest_graph_generation,
        )
        try:
            _persist_embedding_cache(settings.embedding_cache_path, settings.embedding_model_name, dim, cache_entries)
        except Exception as exc:
            LOGGER.warning("Failed to persist embedding cache: %s", exc)
        LOGGER.info("Saved FAISS index to %s and signature map to %s", index_path, sigmap_full_path)
        if progress_callback:
            progress_callback("embedding", "Embedding build complete.", 98.0)
