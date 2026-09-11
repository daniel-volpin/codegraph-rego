from __future__ import annotations

import json
import sys
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import pytest

from codegraph.search import hybrid
from codegraph.search import service as search_service


def test_native_faiss_roundtrip_preserves_method_neighbors(tmp_path: Path) -> None:
    import faiss
    import numpy as np

    keys = ["workspace@revision:A.java#first", "workspace@revision:A.java#near", "workspace@revision:A.java#far"]
    index = faiss.IndexFlatIP(2)
    index.add(np.asarray([[1.0, 0.0], [0.8, 0.6], [0.0, 1.0]], dtype="float32"))
    artifact = tmp_path / "methods.index"
    faiss.write_index(index, str(artifact))
    restored = faiss.read_index(str(artifact))

    assert hybrid.semantic_search_by_method_vector(keys[0], restored, keys, k=5) == [
        "workspace@revision:A.java#near",
        "workspace@revision:A.java#far",
    ]


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
        signature_map_path=settings_obj.signature_map_path_full,
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
        signature_map_path=settings_obj.signature_map_path_full,
        model_name="model-A",
    )
    explicit_service = search_service.HybridSearchService(
        index_path=str(explicit_index),
        signature_map_path=str(explicit_map),
        model_name="model-A",
    )
    assert managed_service.search("q", top_k=1) == ["managed-0"]
    assert explicit_service.search("q", top_k=1) == ["explicit-0"]


def test_search_raises_when_canonical_signature_map_missing(monkeypatch) -> None:
    monkeypatch.setattr(
        search_service,
        "load_search_artifacts_bundle",
        lambda **_kwargs: (_ for _ in ()).throw(FileNotFoundError("not found")),
    )
    service = search_service.HybridSearchService(
        index_path="managed.index",
        signature_map_path="missing.json",
        model_name="model",
    )
    with pytest.raises(FileNotFoundError, match="not found"):
        service.search("needle", top_k=1)


def test_default_search_service_uses_only_canonical_method_key_map(monkeypatch) -> None:
    settings_obj = SimpleNamespace(
        faiss_index_path="managed.index",
        signature_map_path_full="canonical-method-key-map.json",
        signature_map_path="old-signature-map.json",
        embedding_model_name="model-A",
    )
    observed: list[str] = []

    def _load_bundle(*, index_path, signature_map_path):
        observed.append(signature_map_path)
        raise FileNotFoundError(signature_map_path)

    monkeypatch.setattr(search_service, "settings", settings_obj)
    monkeypatch.setattr(search_service, "load_search_artifacts_bundle", _load_bundle)

    service = search_service.HybridSearchService()
    with pytest.raises(FileNotFoundError, match="canonical-method-key-map"):
        service.search("needle", top_k=1)

    assert observed == ["canonical-method-key-map.json"]


def test_validate_search_artifact_generation_uses_canonical_bundle(monkeypatch) -> None:
    generation = SimpleNamespace(
        generation_id="gen-1",
        model="model-A",
        dim=3,
        count=2,
        index_path=Path("index/gen.index"),
        signature_map_path=Path("index/gen-map.json"),
    )
    bundle = SimpleNamespace(
        generation=generation,
        index=SimpleNamespace(ntotal=2, d=3),
        signature_map=["method-key-a", "method-key-b"],
    )
    monkeypatch.setattr(hybrid, "load_search_artifacts_bundle", lambda **_kwargs: bundle)

    metadata = hybrid.validate_search_artifact_generation()

    assert metadata == {
        "generation_id": "gen-1",
        "model": "model-A",
        "dim": 3,
        "count": 2,
        "index_path": "index/gen.index",
        "signature_map_path": "index/gen-map.json",
        "graph_generation": None,
    }


def test_validate_retrieval_generation_matches_active_graph_to_artifact(monkeypatch) -> None:
    graph = {
        "workspace_revisions": 1,
        "method_count": 2,
        "indexable_method_count": 1,
        "schema_versions": ["codegraph-jdt/v1"],
        "parser_backends": ["eclipse-jdt"],
        "active_revisions": [
            {
                "workspace_id": "workspace",
                "revision_id": "revision",
                "schema_version": "codegraph-jdt/v1",
                "parser_backend": "eclipse-jdt",
                "parser_version": "3.47.0",
                "adapter_version": "0.1.0",
                "method_count": 2,
                "indexable_method_count": 1,
            }
        ],
    }
    artifact = {
        "generation_id": "gen-1",
        "model": "model-A",
        "dim": 3,
        "count": 2,
        "index_path": "index/gen.index",
        "signature_map_path": "index/gen-map.json",
        "graph_generation": graph,
    }
    monkeypatch.setattr(hybrid, "_validate_graph_generation", lambda driver, **_kwargs: graph)
    monkeypatch.setattr(hybrid, "validate_search_artifact_generation", lambda: artifact)

    with pytest.raises(hybrid.GenerationMismatchError, match="indexable"):
        hybrid.validate_retrieval_generation(object())

    artifact["count"] = 1
    assert hybrid.validate_retrieval_generation(object()) == {"graph": graph, "artifact": artifact}


def test_validate_retrieval_generation_rejects_stale_artifact_manifest(monkeypatch) -> None:
    graph = {
        "workspace_revisions": 1,
        "method_count": 3,
        "indexable_method_count": 2,
        "schema_versions": ["codegraph-jdt/v1"],
        "parser_backends": ["eclipse-jdt"],
        "active_revisions": [
            {
                "workspace_id": "workspace",
                "revision_id": "new",
                "schema_version": "codegraph-jdt/v1",
                "parser_backend": "eclipse-jdt",
                "parser_version": "3.47.0",
                "adapter_version": "0.1.0",
                "method_count": 3,
                "indexable_method_count": 2,
            }
        ],
    }
    artifact = {
        "generation_id": "gen-1",
        "model": "model-A",
        "dim": 3,
        "count": 2,
        "index_path": "index/gen.index",
        "signature_map_path": "index/gen-map.json",
        "graph_generation": {
            **graph,
            "method_count": 2,
            "indexable_method_count": 1,
            "active_revisions": [
                {
                    **graph["active_revisions"][0],
                    "revision_id": "old",
                    "method_count": 2,
                    "indexable_method_count": 1,
                }
            ],
        },
    }
    monkeypatch.setattr(hybrid, "_validate_graph_generation", lambda driver, **_kwargs: graph)
    monkeypatch.setattr(hybrid, "validate_search_artifact_generation", lambda: artifact)

    with pytest.raises(hybrid.GenerationMismatchError, match="stale"):
        hybrid.validate_retrieval_generation(object())


def test_hybrid_search_service_uses_one_signature_map_path_without_fallback(monkeypatch) -> None:
    observed: list[str | None] = []

    def _load_bundle(*, index_path, signature_map_path):
        observed.append(signature_map_path)
        raise FileNotFoundError("missing canonical method-key map")

    monkeypatch.setattr(search_service, "load_search_artifacts_bundle", _load_bundle)

    service = search_service.HybridSearchService(
        index_path="managed.index",
        signature_map_path="canonical.json",
        model_name="model",
    )

    with pytest.raises(FileNotFoundError, match="canonical"):
        service.search("needle", top_k=1)
    assert observed == ["canonical.json"]


def test_run_search_validates_retrieval_generation_before_query(monkeypatch) -> None:
    events: list[str] = []

    class _Driver:
        pass

    def _shared_driver():
        events.append("driver")
        return _Driver()

    def _validate(driver):
        assert isinstance(driver, _Driver)
        events.append("validate")

    class _Service:
        def search(self, query, top_k):
            events.append(f"search:{query}:{top_k}")
            return ["method-key"]

    monkeypatch.setattr(search_service, "shared_neo4j_driver", _shared_driver)
    monkeypatch.setattr(search_service, "validate_retrieval_generation", _validate)
    monkeypatch.setattr(search_service, "HybridSearchService", _Service)
    monkeypatch.setattr(search_service, "fetch_graph_context_for_method", lambda method_key, driver: [{"method": "display"}])

    assert search_service.run_search("needle", k=1) == (["method-key"], [[{"method": "display"}]])
    assert events == ["driver", "validate", "search:needle:1"]


def test_similar_to_method_key_uses_stored_vector_not_opaque_key_text(monkeypatch) -> None:
    class _Index:
        ntotal = 3
        d = 2

        def reconstruct(self, idx):
            return [0.2, 0.8] if idx == 1 else [0.0, 0.0]

        def search(self, vectors, k):
            assert vectors.tolist()[0] == pytest.approx([0.2, 0.8])
            return [], [[1, 2, 0]]

    monkeypatch.setattr(
        search_service.HybridSearchService,
        "_load_artifacts_bundle",
        lambda self: SimpleNamespace(
            index=_Index(),
            signature_map=["method-a", "method-key", "method-b"],
            generation=SimpleNamespace(dim=2),
        ),
    )
    monkeypatch.setattr(
        search_service.HybridSearchService,
        "_load_model",
        lambda self: (_ for _ in ()).throw(AssertionError("must not embed opaque method_key as query text")),
    )

    service = search_service.HybridSearchService()
    assert service.similar_to_method_key("method-key", top_k=2) == ["method-b", "method-a"]


def test_similar_to_method_key_rejects_missing_method_key(monkeypatch) -> None:
    monkeypatch.setattr(
        search_service.HybridSearchService,
        "_load_artifacts_bundle",
        lambda self: SimpleNamespace(index=SimpleNamespace(ntotal=1), signature_map=["method-a"], generation=None),
    )

    with pytest.raises(KeyError, match="method_key not found"):
        search_service.HybridSearchService().similar_to_method_key("missing")
