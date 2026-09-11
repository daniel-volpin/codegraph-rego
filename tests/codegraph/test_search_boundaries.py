import os
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from codegraph.search import hybrid


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
