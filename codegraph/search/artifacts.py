from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class ArtifactConsistencyError(ValueError):
    """Raised when embedding artifacts cannot be proven consistent."""


@dataclass(frozen=True)
class ActiveEmbeddingGeneration:
    generation_id: str
    model: str
    dim: int | None
    count: int
    index_path: Path
    signature_map_path: Path
    metadata_path: Path
    index_sha256: str
    signature_map_sha256: str
    metadata_sha256: str


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _require_path(value: object, *, field: str) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise ArtifactConsistencyError(f"Invalid generation manifest: {field} must be a non-empty string path")
    return Path(value).resolve()


def _require_sha(value: object, *, field: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise ArtifactConsistencyError(f"Invalid generation manifest: {field} must be a sha256 hex digest")
    return value


def _require_int(value: object, *, field: str, allow_none: bool = False) -> int | None:
    if value is None and allow_none:
        return None
    if not isinstance(value, int) or value < 0:
        raise ArtifactConsistencyError(f"Invalid generation manifest: {field} must be a non-negative integer")
    return value


def _validate_signature_map(path: Path) -> int:
    payload = _read_json(path)
    if not isinstance(payload, list) or any(not isinstance(v, str) or not v for v in payload):
        raise ArtifactConsistencyError(f"Invalid signature map at {path}: expected a list of method identifiers")
    return len(payload)


def load_active_generation(manifest_path: str | Path) -> ActiveEmbeddingGeneration:
    path = Path(manifest_path).resolve()
    payload = _read_json(path)
    if not isinstance(payload, dict):
        raise ArtifactConsistencyError("Invalid generation manifest: expected a JSON object")
    if payload.get("schema") != "embedding_generation_manifest.v1":
        if any(key in payload for key in ("model", "index_path", "signature_map")):
            raise ArtifactConsistencyError(
                "Legacy embedding metadata format is unsupported for managed search. "
                "Rebuild embeddings to publish embedding_generation_manifest.v1."
            )
        raise ArtifactConsistencyError("Invalid generation manifest schema")
    generation = payload.get("generation")
    if not isinstance(generation, dict):
        raise ArtifactConsistencyError("Invalid generation manifest: missing generation object")
    generation_id = generation.get("id")
    if not isinstance(generation_id, str) or not generation_id:
        raise ArtifactConsistencyError("Invalid generation manifest: generation.id must be a non-empty string")
    model = generation.get("model")
    if not isinstance(model, str) or not model:
        raise ArtifactConsistencyError("Invalid generation manifest: generation.model must be a non-empty string")
    dim = _require_int(generation.get("dim"), field="generation.dim", allow_none=True)
    count = _require_int(generation.get("count"), field="generation.count")
    metadata = generation.get("metadata")
    if not isinstance(metadata, dict):
        raise ArtifactConsistencyError("Invalid generation manifest: missing generation.metadata object")

    index_path = _require_path(metadata.get("index_path"), field="generation.metadata.index_path")
    map_path = _require_path(metadata.get("signature_map_path"), field="generation.metadata.signature_map_path")
    metadata_path = _require_path(metadata.get("metadata_path"), field="generation.metadata.metadata_path")
    index_sha = _require_sha(metadata.get("index_sha256"), field="generation.metadata.index_sha256")
    map_sha = _require_sha(metadata.get("signature_map_sha256"), field="generation.metadata.signature_map_sha256")
    metadata_sha = _require_sha(metadata.get("metadata_sha256"), field="generation.metadata.metadata_sha256")

    for artifact_path, artifact_name in (
        (index_path, "index"),
        (map_path, "signature map"),
        (metadata_path, "metadata"),
    ):
        if not artifact_path.is_file():
            raise ArtifactConsistencyError(
                f"Active generation {generation_id} is unreadable: missing {artifact_name} artifact at {artifact_path}"
            )

    current_index_sha = sha256_file(index_path)
    if current_index_sha != index_sha:
        raise ArtifactConsistencyError(
            f"Active generation {generation_id} index hash mismatch at {index_path}: expected {index_sha}, got {current_index_sha}"
        )
    current_map_sha = sha256_file(map_path)
    if current_map_sha != map_sha:
        raise ArtifactConsistencyError(
            f"Active generation {generation_id} signature map hash mismatch at {map_path}: "
            f"expected {map_sha}, got {current_map_sha}"
        )
    current_metadata_sha = sha256_file(metadata_path)
    if current_metadata_sha != metadata_sha:
        raise ArtifactConsistencyError(
            f"Active generation {generation_id} metadata hash mismatch at {metadata_path}: "
            f"expected {metadata_sha}, got {current_metadata_sha}"
        )

    metadata_payload = _read_json(metadata_path)
    if not isinstance(metadata_payload, dict):
        raise ArtifactConsistencyError(f"Invalid generation metadata at {metadata_path}: expected a JSON object")
    metadata_model = metadata_payload.get("model")
    metadata_dim = metadata_payload.get("dim")
    metadata_count = metadata_payload.get("count")
    if metadata_model != model:
        raise ArtifactConsistencyError(
            f"Active generation {generation_id} model mismatch between manifest ({model}) and metadata ({metadata_model})"
        )
    if metadata_dim != dim:
        raise ArtifactConsistencyError(
            f"Active generation {generation_id} dimension mismatch between manifest ({dim}) and metadata ({metadata_dim})"
        )
    if metadata_count != count:
        raise ArtifactConsistencyError(
            f"Active generation {generation_id} count mismatch between manifest ({count}) and metadata ({metadata_count})"
        )
    map_count = _validate_signature_map(map_path)
    if map_count != count:
        raise ArtifactConsistencyError(
            f"Active generation {generation_id} count mismatch: manifest count={count}, signature map entries={map_count}"
        )

    return ActiveEmbeddingGeneration(
        generation_id=generation_id,
        model=model,
        dim=dim,
        count=count,
        index_path=index_path,
        signature_map_path=map_path,
        metadata_path=metadata_path,
        index_sha256=index_sha,
        signature_map_sha256=map_sha,
        metadata_sha256=metadata_sha,
    )
