import json
import os
import sys
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from codegraph.search import hybrid


def _sha(path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def _write_generation_manifest(tmp_path, *, model: str = "test-model", dim: int = 1, count: int = 1) -> SimpleNamespace:
    index_path = tmp_path / "gen.index"
    map_path = tmp_path / "gen_map.json"
    metadata_path = tmp_path / "gen_meta.json"
    index_path.write_bytes(b"index-bytes")
    map_payload = [f"method-{idx}" for idx in range(count)] if count > 1 else ["method-a"]
    map_path.write_text(json.dumps(map_payload), encoding="utf-8")
    metadata_path.write_text(
        f'{{"model":"{model}","dim":{dim},"count":{count}}}',
        encoding="utf-8",
    )
    manifest_path = tmp_path / "embedding_metadata.json"
    manifest_path.write_text(
        (
            "{"
            '"schema":"embedding_generation_manifest.v1",'
            '"generation":{'
            '"id":"g1",'
            f'"model":"{model}",'
            f'"dim":{dim},'
            f'"count":{count},'
            '"metadata":{'
            f'"index_path":"{index_path}",'
            f'"index_sha256":"{_sha(index_path)}",'
            f'"signature_map_path":"{map_path}",'
            f'"signature_map_sha256":"{_sha(map_path)}",'
            f'"metadata_path":"{metadata_path}",'
            f'"metadata_sha256":"{_sha(metadata_path)}"'
            "}}}"
        ),
        encoding="utf-8",
    )
    configured_index = tmp_path / "code_embeddings.index"
    configured_map = tmp_path / "embedding_full_signature_map.json"
    configured_legacy_map = tmp_path / "embedding_signature_map.json"
    return SimpleNamespace(
        embedding_metadata_path=str(manifest_path),
        faiss_index_path=str(configured_index),
        signature_map_path_full=str(configured_map),
        signature_map_path=str(configured_legacy_map),
        embedding_model_name=model,
    )


def test_missing_faiss_neighbors_do_not_become_unrelated_citations() -> None:
    model = SimpleNamespace(encode=lambda *_args, **_kwargs: [[1.0]])
    index = SimpleNamespace(ntotal=2, search=lambda *_args, **_kwargs: ([], [[0, -1, 1, -1]]))
    assert hybrid.semantic_search("query", model, index, ["method-a", "method-b"], k=4) == ["method-a", "method-b"]


def test_empty_index_returns_no_citations_without_loading_embeddings() -> None:
    model = SimpleNamespace(encode=Mock(side_effect=AssertionError("must not encode an empty index")))
    index = SimpleNamespace(ntotal=0)
    assert hybrid.semantic_search("query", model, index, [], k=3) == []


def test_mismatched_signature_map_is_rejected() -> None:
    model = SimpleNamespace(encode=lambda *_args, **_kwargs: [[1.0]])
    index = SimpleNamespace(ntotal=2, search=lambda *_args, **_kwargs: ([], [[0]]))
    with pytest.raises(ValueError, match="signature map"):
        hybrid.semantic_search("query", model, index, ["only-one"], k=1)


def test_explicit_signature_map_does_not_load_another_workspace(tmp_path, monkeypatch) -> None:
    requested = tmp_path / "requested.json"
    unrelated = tmp_path / "unrelated.json"
    requested.write_text('["requested-method"]', encoding="utf-8")
    unrelated.write_text('["unrelated-method"]', encoding="utf-8")
    monkeypatch.setattr(
        hybrid, "settings",
        SimpleNamespace(signature_map_path_full=str(unrelated), signature_map_path=str(unrelated)),
    )
    monkeypatch.setattr(hybrid, "_SIGMAP", None)
    assert hybrid.load_signature_map(str(requested)) == ["requested-method"]


@pytest.mark.parametrize("payload", ['{"not": "a list"}', '[1, "method"]'])
def test_invalid_signature_map_is_not_accepted(tmp_path, monkeypatch, payload) -> None:
    requested = tmp_path / "invalid.json"
    requested.write_text(payload, encoding="utf-8")
    monkeypatch.setattr(hybrid, "_SIGMAP", None)
    with pytest.raises(ValueError, match="signature map"):
        hybrid.load_signature_map(str(requested))


def test_index_cache_distinguishes_files_with_the_same_timestamp(tmp_path, monkeypatch) -> None:
    first = tmp_path / "first.index"
    second = tmp_path / "second.index"
    for path in (first, second):
        path.write_bytes(b"index")
        os.utime(path, ns=(1_000_000_000, 1_000_000_000))
    monkeypatch.setattr(hybrid, "_INDEX", None)
    monkeypatch.setitem(sys.modules, "faiss", SimpleNamespace(read_index=lambda path: path))
    assert hybrid.load_faiss_index(str(first)) == str(first)
    assert hybrid.load_faiss_index(str(second)) == str(second)


def test_embedding_cache_respects_requested_model(monkeypatch) -> None:
    monkeypatch.setattr(hybrid, "_MODEL", None)
    monkeypatch.setitem(
        sys.modules, "sentence_transformers",
        SimpleNamespace(SentenceTransformer=lambda name: SimpleNamespace(name=name)),
    )
    assert hybrid.load_embedding_model("first-model").name == "first-model"
    assert hybrid.load_embedding_model("second-model").name == "second-model"


def test_k_greater_than_index_size_returns_available_unique_signatures() -> None:
    model = SimpleNamespace(encode=lambda *_args, **_kwargs: [[1.0]])
    index = SimpleNamespace(ntotal=2, d=1, search=lambda *_args, **_kwargs: ([], [[0, 1, 1, -1]]))
    assert hybrid.semantic_search("query", model, index, ["method-a", "method-b"], k=10) == ["method-a", "method-b"]


def test_generation_manifest_hash_mismatch_is_rejected(tmp_path, monkeypatch) -> None:
    settings_obj = _write_generation_manifest(tmp_path)
    payload = (tmp_path / "embedding_metadata.json").read_text(encoding="utf-8").replace(
        f'"signature_map_sha256":"{_sha(tmp_path / "gen_map.json")}"',
        '"signature_map_sha256":"' + ("0" * 64) + '"',
    )
    (tmp_path / "embedding_metadata.json").write_text(payload, encoding="utf-8")
    monkeypatch.setattr(hybrid, "settings", settings_obj)
    monkeypatch.setattr(hybrid, "_SIGMAP", None)
    with pytest.raises(ValueError, match="hash mismatch"):
        hybrid.load_signature_map(settings_obj.signature_map_path_full)


def test_semantic_search_rejects_manifest_model_mismatch(tmp_path, monkeypatch) -> None:
    settings_obj = _write_generation_manifest(tmp_path, model="model-a", dim=3)
    monkeypatch.setattr(hybrid, "settings", settings_obj)
    monkeypatch.setitem(sys.modules, "faiss", SimpleNamespace(read_index=lambda _path: SimpleNamespace(ntotal=1, d=3)))
    bundle = hybrid.load_search_artifacts_bundle(
        index_path=settings_obj.faiss_index_path,
        signature_map_path=settings_obj.signature_map_path_full,
    )
    with pytest.raises(ValueError, match="model mismatch"):
        hybrid.semantic_search(
            "query",
            SimpleNamespace(encode=lambda *_args, **_kwargs: [[0.1, 0.2, 0.3]]),
            bundle.index,
            bundle.signature_map,
            k=1,
            generation=bundle.generation,
            expected_model_name="model-b",
        )


def test_semantic_search_rejects_manifest_dimension_mismatch(tmp_path, monkeypatch) -> None:
    settings_obj = _write_generation_manifest(tmp_path, model="model-a", dim=4)
    monkeypatch.setattr(hybrid, "settings", settings_obj)
    monkeypatch.setitem(sys.modules, "faiss", SimpleNamespace(read_index=lambda _path: SimpleNamespace(ntotal=1, d=4)))
    bundle = hybrid.load_search_artifacts_bundle(
        index_path=settings_obj.faiss_index_path,
        signature_map_path=settings_obj.signature_map_path_full,
    )
    with pytest.raises(ValueError, match="dimension mismatch"):
        hybrid.semantic_search(
            "query",
            SimpleNamespace(encode=lambda *_args, **_kwargs: [[0.1, 0.2, 0.3]]),
            bundle.index,
            bundle.signature_map,
            k=1,
            generation=bundle.generation,
            expected_model_name="model-a",
        )


def test_managed_load_rejects_legacy_metadata_schema(tmp_path, monkeypatch) -> None:
    old_metadata = tmp_path / "embedding_metadata.json"
    old_metadata.write_text('{"model":"legacy","index_path":"x","signature_map":{"full":"y"}}', encoding="utf-8")
    settings_obj = SimpleNamespace(
        embedding_metadata_path=str(old_metadata),
        faiss_index_path=str(tmp_path / "legacy.index"),
        signature_map_path_full=str(tmp_path / "legacy_map_full.json"),
        signature_map_path=str(tmp_path / "legacy_map.json"),
        embedding_model_name="legacy",
    )
    monkeypatch.setattr(hybrid, "settings", settings_obj)
    with pytest.raises(ValueError, match="Legacy embedding metadata format is unsupported"):
        hybrid.load_search_artifacts_bundle()


def test_invalid_managed_index_is_rejected_on_every_call_not_cached(tmp_path, monkeypatch) -> None:
    settings_obj = _write_generation_manifest(tmp_path, count=2)
    read_calls = {"count": 0}

    def _read_index(_path):
        read_calls["count"] += 1
        return SimpleNamespace(ntotal=1, d=1)

    monkeypatch.setattr(hybrid, "settings", settings_obj)
    monkeypatch.setattr(hybrid, "_INDEX", None)
    monkeypatch.setitem(sys.modules, "faiss", SimpleNamespace(read_index=_read_index))
    with pytest.raises(ValueError, match="different method counts"):
        hybrid.load_search_artifacts_bundle()
    with pytest.raises(ValueError, match="different method counts"):
        hybrid.load_search_artifacts_bundle()
    assert read_calls["count"] == 2


def test_managed_artifact_corruption_after_first_load_is_rejected_without_manifest_change(tmp_path, monkeypatch) -> None:
    settings_obj = _write_generation_manifest(tmp_path, count=1)
    monkeypatch.setattr(hybrid, "settings", settings_obj)
    monkeypatch.setitem(sys.modules, "faiss", SimpleNamespace(read_index=lambda _path: SimpleNamespace(ntotal=1, d=1)))
    first = hybrid.load_search_artifacts_bundle()
    assert first.signature_map == ["method-a"]

    manifest_path = tmp_path / "embedding_metadata.json"
    manifest_payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    map_path = Path(manifest_payload["generation"]["metadata"]["signature_map_path"])
    map_path.write_text('["method-b"]', encoding="utf-8")

    with pytest.raises(ValueError, match="hash mismatch"):
        hybrid.load_search_artifacts_bundle()


def test_explicit_signature_map_remains_isolated_after_managed_load(tmp_path, monkeypatch) -> None:
    settings_obj = _write_generation_manifest(tmp_path, count=1)
    explicit_map = tmp_path / "explicit.json"
    explicit_map.write_text('["explicit-method"]', encoding="utf-8")
    monkeypatch.setattr(hybrid, "settings", settings_obj)
    monkeypatch.setattr(hybrid, "_SIGMAP", None)

    assert hybrid.load_signature_map() == ["method-a"]
    assert hybrid.load_signature_map(str(explicit_map)) == ["explicit-method"]
