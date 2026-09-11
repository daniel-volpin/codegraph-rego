from __future__ import annotations

import json
import sys
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import pytest

from codegraph.search import service as search_service


def _sha(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _write_generation(
    tmp_path: Path,
    *,
    generation_id: str,
    signatures: list[str],
    search_index: int,
) -> dict[str, str]:
    index_path = tmp_path / f"code_embeddings.{generation_id}.index"
    map_path = tmp_path / f"embedding_full_signature_map.{generation_id}.json"
    metadata_path = tmp_path / f"embedding_metadata.{generation_id}.json"
    index_path.write_bytes(json.dumps({"ntotal": len(signatures), "d": 1, "pick": search_index}).encode("utf-8"))
    map_path.write_text(json.dumps(signatures), encoding="utf-8")
    metadata_path.write_text(
        json.dumps({"model": "model-A", "dim": 1, "count": len(signatures)}),
        encoding="utf-8",
    )
    return {
        "id": generation_id,
        "index_path": str(index_path),
        "signature_map_path": str(map_path),
        "metadata_path": str(metadata_path),
        "index_sha256": _sha(index_path),
        "signature_map_sha256": _sha(map_path),
        "metadata_sha256": _sha(metadata_path),
    }


def _write_manifest(path: Path, generation: dict[str, str], count: int) -> None:
    payload = {
        "schema": "embedding_generation_manifest.v1",
        "generation": {
            "id": generation["id"],
            "model": "model-A",
            "dim": 1,
            "count": count,
            "metadata": {
                "index_path": generation["index_path"],
                "index_sha256": generation["index_sha256"],
                "signature_map_path": generation["signature_map_path"],
                "signature_map_sha256": generation["signature_map_sha256"],
                "metadata_path": generation["metadata_path"],
                "metadata_sha256": generation["metadata_sha256"],
            },
        },
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


def _fake_faiss_module():
    def _read_index(path: str):
        payload = json.loads(Path(path).read_bytes().decode("utf-8"))
        pick = int(payload["pick"])
        return SimpleNamespace(
            ntotal=int(payload["ntotal"]),
            d=int(payload["d"]),
            search=lambda *_args, **_kwargs: ([], [[pick]]),
        )

    return SimpleNamespace(read_index=_read_index)


def test_search_pins_single_generation_when_manifest_switches_mid_load(tmp_path, monkeypatch) -> None:
    from codegraph.search import hybrid

    manifest = tmp_path / "embedding_metadata.json"
    old_gen = _write_generation(tmp_path, generation_id="old", signatures=["old-0", "old-1"], search_index=1)
    new_gen = _write_generation(tmp_path, generation_id="new", signatures=["new-0", "new-1"], search_index=0)
    _write_manifest(manifest, old_gen, 2)

    settings_obj = SimpleNamespace(
        embedding_metadata_path=str(manifest),
        faiss_index_path=str(tmp_path / "code_embeddings.index"),
        signature_map_path_full=str(tmp_path / "embedding_full_signature_map.json"),
        signature_map_path=str(tmp_path / "embedding_signature_map.json"),
        embedding_model_name="model-A",
    )
    monkeypatch.setattr(hybrid, "settings", settings_obj)
    monkeypatch.setattr(search_service, "settings", settings_obj)
    monkeypatch.setattr(hybrid, "_INDEX", None)
    monkeypatch.setattr(hybrid, "_INDEX_MTIME", None)
    monkeypatch.setattr(hybrid, "_SIGMAP", None)
    monkeypatch.setattr(hybrid, "_SIGMAP_MTIME", None)
    monkeypatch.setitem(sys.modules, "faiss", _fake_faiss_module())
    monkeypatch.setattr(
        search_service,
        "load_embedding_model",
        lambda _name: SimpleNamespace(encode=lambda *_args, **_kwargs: [[1.0]]),
    )

    original_resolve = hybrid._resolve_active_generation
    switch_state = {"done": False}

    def _resolve_and_switch(*, required: bool):
        if not switch_state["done"]:
            generation = original_resolve(required=required)
            _write_manifest(manifest, new_gen, 2)
            switch_state["done"] = True
            return generation
        return original_resolve(required=required)

    monkeypatch.setattr(hybrid, "_resolve_active_generation", _resolve_and_switch)

    service = search_service.HybridSearchService(
        index_path=settings_obj.faiss_index_path,
        signature_map_candidates=(settings_obj.signature_map_path_full,),
        model_name="model-A",
    )
    first = service.search("needle", top_k=1)
    second = service.search("needle", top_k=1)
    assert first == ["old-1"]
    assert second == ["new-0"]


def test_search_uses_real_bundle_with_explicit_path_isolation(tmp_path, monkeypatch) -> None:
    from codegraph.search import hybrid

    manifest = tmp_path / "embedding_metadata.json"
    managed = _write_generation(tmp_path, generation_id="managed", signatures=["managed-0"], search_index=0)
    _write_manifest(manifest, managed, 1)
    explicit_index = tmp_path / "external.index"
    explicit_index.write_bytes(json.dumps({"ntotal": 1, "d": 1, "pick": 0}).encode("utf-8"))
    explicit_map = tmp_path / "external_map.json"
    explicit_map.write_text('["explicit-0"]', encoding="utf-8")

    settings_obj = SimpleNamespace(
        embedding_metadata_path=str(manifest),
        faiss_index_path=str(tmp_path / "code_embeddings.index"),
        signature_map_path_full=str(tmp_path / "embedding_full_signature_map.json"),
        signature_map_path=str(tmp_path / "embedding_signature_map.json"),
        embedding_model_name="model-A",
    )
    monkeypatch.setattr(hybrid, "settings", settings_obj)
    monkeypatch.setattr(search_service, "settings", settings_obj)
    monkeypatch.setattr(hybrid, "_INDEX", None)
    monkeypatch.setattr(hybrid, "_SIGMAP", None)
    monkeypatch.setitem(sys.modules, "faiss", _fake_faiss_module())
    monkeypatch.setattr(
        search_service,
        "load_embedding_model",
        lambda _name: SimpleNamespace(encode=lambda *_args, **_kwargs: [[1.0]]),
    )

    managed_service = search_service.HybridSearchService(
        index_path=settings_obj.faiss_index_path,
        signature_map_candidates=(settings_obj.signature_map_path_full,),
        model_name="model-A",
    )
    explicit_service = search_service.HybridSearchService(
        index_path=str(explicit_index),
        signature_map_candidates=(str(explicit_map),),
        model_name="model-A",
    )
    assert managed_service.search("q", top_k=1) == ["managed-0"]
    assert explicit_service.search("q", top_k=1) == ["explicit-0"]


def test_search_raises_when_no_signature_map_candidates(monkeypatch) -> None:
    monkeypatch.setattr(
        search_service,
        "load_search_artifacts_bundle",
        lambda **_kwargs: (_ for _ in ()).throw(FileNotFoundError("not found")),
    )
    service = search_service.HybridSearchService(
        index_path="managed.index",
        signature_map_candidates=("missing1.json", "missing2.json"),
        model_name="model",
    )
    with pytest.raises(FileNotFoundError, match="not found"):
        service.search("needle", top_k=1)
