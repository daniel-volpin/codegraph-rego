from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from codegraph.embedding import service as embedding_service


class _FakeVector:
    def __init__(self, values: list[float]) -> None:
        self._values = values

    def tolist(self) -> list[float]:
        return list(self._values)


class _FakeArray:
    def __init__(self, values: list[list[float]], *, dtype: str = "float32") -> None:
        self._values = values
        self.ndim = 2
        rows = len(values)
        cols = len(values[0]) if rows else 0
        self.shape = (rows, cols)
        self.dtype = dtype

    def __getitem__(self, item: int) -> _FakeVector:
        return _FakeVector(self._values[item])

    def tolist(self) -> list[list[float]]:
        return [list(row) for row in self._values]


def _fake_faiss_module():
    class _FakeIndex:
        def __init__(self, dim: int) -> None:
            self.d = dim
            self.ntotal = 0
            self._vectors: list[list[float]] = []

        def add(self, vectors) -> None:
            self._vectors = vectors.tolist()
            self.ntotal = len(self._vectors)

    def _write_index(index: _FakeIndex, path: str) -> None:
        payload = json.dumps({"d": index.d, "ntotal": index.ntotal, "vectors": index._vectors}).encode("utf-8")
        with open(path, "wb") as handle:
            handle.write(payload)

    def _read_index(path: str):
        payload = json.loads(Path(path).read_bytes().decode("utf-8"))
        return SimpleNamespace(
            d=payload["d"],
            ntotal=payload["ntotal"],
            search=lambda *_args, **_kwargs: ([], [[0] if payload["ntotal"] else [-1]]),
        )

    return SimpleNamespace(IndexFlatIP=_FakeIndex, write_index=_write_index, read_index=_read_index)


def _fake_numpy_module() -> SimpleNamespace:
    return SimpleNamespace(asarray=lambda values, dtype=None: _FakeArray(values, dtype=dtype or "float32"))


def _make_settings(tmp_path):
    index_dir = tmp_path / "index"
    return SimpleNamespace(
        index_dir=str(index_dir),
        faiss_index_path=str(index_dir / "code_embeddings.index"),
        signature_map_path=str(index_dir / "embedding_signature_map.json"),
        signature_map_path_full=str(index_dir / "embedding_full_signature_map.json"),
        embedding_metadata_path=str(index_dir / "embedding_metadata.json"),
        embedding_cache_path=str(index_dir / "embedding_cache.json"),
        embedding_model_name="test-model",
    )


def test_build_embeddings_writes_atomic_generation_manifest(tmp_path, monkeypatch) -> None:
    settings_obj = _make_settings(tmp_path)
    monkeypatch.setattr(embedding_service, "settings", settings_obj)
    monkeypatch.setattr(
        embedding_service,
        "_fetch_method_snippets",
        lambda: [embedding_service._MethodSnippet(signature="pkg.A#a()", code="class A {}")],
    )
    monkeypatch.setitem(sys.modules, "faiss", _fake_faiss_module())
    monkeypatch.setitem(sys.modules, "numpy", _fake_numpy_module())
    monkeypatch.setitem(
        sys.modules,
        "sentence_transformers",
        SimpleNamespace(
            SentenceTransformer=lambda _name: SimpleNamespace(
                encode=lambda *_a, **_k: _FakeArray([[1.0]], dtype="float32")
            )
        ),
    )

    embedding_service.EmbeddingService.build_embeddings()

    manifest_path = tmp_path / "index" / "embedding_metadata.json"
    assert manifest_path.exists()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["schema"] == "embedding_generation_manifest.v1"
    generation = manifest["generation"]
    assert isinstance(generation["id"], str) and len(generation["id"]) == 32
    assert generation["model"] == "test-model"
    assert generation["dim"] == 1
    assert generation["count"] == 1
    metadata = generation["metadata"]
    for key in ("index_path", "signature_map_path", "metadata_path"):
        assert Path(metadata[key]).is_file()  # type: ignore[name-defined]
    for key in ("index_sha256", "signature_map_sha256", "metadata_sha256"):
        assert len(metadata[key]) == 64
    assert not Path(settings_obj.signature_map_path_full).exists()
    assert not Path(settings_obj.signature_map_path).exists()


def test_build_embeddings_leaves_previous_manifest_readable_on_publish_failure(tmp_path, monkeypatch) -> None:
    from codegraph.search import hybrid

    settings_obj = _make_settings(tmp_path)
    manifest_path = tmp_path / "index" / "embedding_metadata.json"
    monkeypatch.setattr(embedding_service, "settings", settings_obj)
    monkeypatch.setattr(hybrid, "settings", settings_obj)
    monkeypatch.setattr(hybrid, "_INDEX", None)
    monkeypatch.setattr(hybrid, "_INDEX_MTIME", None)
    monkeypatch.setattr(hybrid, "_SIGMAP", None)
    monkeypatch.setattr(hybrid, "_SIGMAP_MTIME", None)
    monkeypatch.setattr(
        embedding_service,
        "_fetch_method_snippets",
        lambda: [embedding_service._MethodSnippet(signature="pkg.A#a()", code="class A1 {}")],
    )
    fake_faiss = _fake_faiss_module()
    monkeypatch.setitem(sys.modules, "faiss", fake_faiss)
    monkeypatch.setitem(sys.modules, "numpy", _fake_numpy_module())
    monkeypatch.setitem(
        sys.modules,
        "sentence_transformers",
        SimpleNamespace(
            SentenceTransformer=lambda _name: SimpleNamespace(
                encode=lambda *_a, **_k: _FakeArray([[1.0]], dtype="float32")
            )
        ),
    )

    embedding_service.EmbeddingService.build_embeddings()
    first_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    first_id = first_manifest["generation"]["id"]

    monkeypatch.setattr(
        embedding_service,
        "_fetch_method_snippets",
        lambda: [embedding_service._MethodSnippet(signature="pkg.A#a()", code="class A2 {}")],
    )
    monkeypatch.setattr(
        embedding_service,
        "_publish_generation_manifest",
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("publish blocked")),
    )

    with pytest.raises(RuntimeError, match="publish blocked"):
        embedding_service.EmbeddingService.build_embeddings()

    current_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert current_manifest["generation"]["id"] == first_id
    bundle = hybrid.load_search_artifacts_bundle()
    results = hybrid.semantic_search(
        "query",
        SimpleNamespace(encode=lambda *_args, **_kwargs: [[1.0]]),
        bundle.index,
        bundle.signature_map,
        k=1,
        generation=bundle.generation,
        expected_model_name=settings_obj.embedding_model_name,
    )
    assert results == ["pkg.A#a()"]


def test_manifest_replace_failure_keeps_previous_manifest_and_leaves_no_temp_orphan(tmp_path, monkeypatch) -> None:
    settings_obj = _make_settings(tmp_path)
    manifest_path = tmp_path / "index" / "embedding_metadata.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text('{"schema":"embedding_generation_manifest.v1","generation":{"id":"stable"}}', encoding="utf-8")
    before = manifest_path.read_text(encoding="utf-8")
    monkeypatch.setattr(embedding_service, "settings", settings_obj)

    original_replace = embedding_service.os.replace

    def _failing_replace(src, dst):
        if Path(dst) == manifest_path:
            raise RuntimeError("replace failed")
        return original_replace(src, dst)

    monkeypatch.setattr(embedding_service.os, "replace", _failing_replace)
    with pytest.raises(RuntimeError, match="replace failed"):
        embedding_service._atomic_write_json(manifest_path, {"schema": "embedding_generation_manifest.v1"})

    assert manifest_path.read_text(encoding="utf-8") == before
    assert list(manifest_path.parent.glob(".embedding_metadata.json.tmp-*")) == []


def test_manifest_serialize_failure_keeps_previous_manifest_and_leaves_no_temp_orphan(tmp_path) -> None:
    settings_obj = _make_settings(tmp_path)
    manifest_path = Path(settings_obj.embedding_metadata_path)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    before = '{"schema":"embedding_generation_manifest.v1","generation":{"id":"stable"}}'
    manifest_path.write_text(before, encoding="utf-8")

    with pytest.raises(TypeError):
        embedding_service._atomic_write_json(manifest_path, {"bad": object()})

    assert manifest_path.read_text(encoding="utf-8") == before
    assert list(manifest_path.parent.glob(".embedding_metadata.json.tmp-*")) == []


def test_build_embeddings_rejects_vector_signature_count_mismatch_before_manifest_switch(tmp_path, monkeypatch) -> None:
    settings_obj = _make_settings(tmp_path)
    monkeypatch.setattr(embedding_service, "settings", settings_obj)
    monkeypatch.setattr(
        embedding_service,
        "_fetch_method_snippets",
        lambda: [
            embedding_service._MethodSnippet(signature="pkg.A#a()", code="class A {}"),
            embedding_service._MethodSnippet(signature="pkg.B#b()", code="class B {}"),
        ],
    )
    monkeypatch.setitem(sys.modules, "faiss", _fake_faiss_module())
    monkeypatch.setitem(sys.modules, "numpy", _fake_numpy_module())
    monkeypatch.setitem(
        sys.modules,
        "sentence_transformers",
        SimpleNamespace(
            SentenceTransformer=lambda _name: SimpleNamespace(
                encode=lambda *_a, **_k: _FakeArray([[1.0], [1.0]], dtype="float32")
            )
        ),
    )
    monkeypatch.setattr(
        embedding_service,
        "_encode_missing_vectors",
        lambda *_args, **_kwargs: {"pkg.A#a()": [1.0]},
    )

    with pytest.raises(RuntimeError, match="vector/signature count mismatch"):
        embedding_service.EmbeddingService.build_embeddings()


def test_fetch_method_snippets_prefers_exact_ranges_for_overloads(tmp_path, monkeypatch) -> None:
    java_file = tmp_path / "Overloads.java"
    java_file.write_text(
        "\n".join(
            [
                "class Overloads {",
                "  void work() {",
                "    int first = 1;",
                "  }",
                "  void work(int n) {",
                "    int second = n;",
                "  }",
                "}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    rows = [
        {
            "sig": "Overloads#work()",
            "name": "work",
            "path": str(java_file),
            "start_line": 2,
            "end_line": 4,
        },
        {
            "sig": "Overloads#work(int)",
            "name": "work",
            "path": str(java_file),
            "start_line": 5,
            "end_line": 7,
        },
    ]

    class _Session:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def run(self, _query):
            return rows

    class _Driver:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def session(self):
            return _Session()

    monkeypatch.setattr(embedding_service.GraphDatabase, "driver", lambda *_args, **_kwargs: _Driver())
    snippets = embedding_service._fetch_method_snippets()
    assert len(snippets) == 2
    assert "int first = 1;" in snippets[0].code
    assert "int second = n;" not in snippets[0].code
    assert "int second = n;" in snippets[1].code
    assert "int first = 1;" not in snippets[1].code


def test_fetch_method_snippets_rejects_ambiguous_missing_range_fallback(tmp_path, monkeypatch, caplog) -> None:
    java_file = tmp_path / "Overloads.java"
    java_file.write_text(
        "\n".join(
            [
                "class Overloads {",
                "  void work() {}",
                "  void work(int n) {}",
                "}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    rows = [
        {"sig": "Overloads#work()", "name": "work", "path": str(java_file), "start_line": None, "end_line": None}
    ]

    class _Session:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def run(self, _query):
            return rows

    class _Driver:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def session(self):
            return _Session()

    monkeypatch.setattr(embedding_service.GraphDatabase, "driver", lambda *_args, **_kwargs: _Driver())
    with caplog.at_level(logging.WARNING):
        snippets = embedding_service._fetch_method_snippets()
    assert snippets == []
    assert "Skipping method snippet for signature Overloads#work()" in caplog.text


def test_fetch_method_snippets_rejects_incomplete_range_without_fallback(tmp_path, monkeypatch, caplog) -> None:
    java_file = tmp_path / "Overloads.java"
    java_file.write_text(
        "\n".join(
            [
                "class Overloads {",
                "  void work() {}",
                "  void work(int n) {}",
                "}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    rows = [
        {"sig": "Overloads#work()", "name": "work", "path": str(java_file), "start_line": 2, "end_line": None}
    ]

    class _Session:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def run(self, _query):
            return rows

    class _Driver:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def session(self):
            return _Session()

    monkeypatch.setattr(embedding_service.GraphDatabase, "driver", lambda *_args, **_kwargs: _Driver())
    with caplog.at_level(logging.WARNING):
        snippets = embedding_service._fetch_method_snippets()
    assert snippets == []
    assert "incomplete source range metadata" in caplog.text


def test_fetch_method_snippets_rejects_out_of_file_range_without_fallback(tmp_path, monkeypatch, caplog) -> None:
    java_file = tmp_path / "Overloads.java"
    java_file.write_text("class Overloads {\n  void work() {}\n}\n", encoding="utf-8")
    rows = [
        {"sig": "Overloads#work()", "name": "work", "path": str(java_file), "start_line": 2, "end_line": 20}
    ]

    class _Session:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def run(self, _query):
            return rows

    class _Driver:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def session(self):
            return _Session()

    monkeypatch.setattr(embedding_service.GraphDatabase, "driver", lambda *_args, **_kwargs: _Driver())
    with caplog.at_level(logging.WARNING):
        snippets = embedding_service._fetch_method_snippets()
    assert snippets == []
    assert "invalid source range 2-20" in caplog.text


def test_manifest_write_failure_keeps_previous_manifest_and_leaves_no_temp_orphan(tmp_path, monkeypatch) -> None:
    settings_obj = _make_settings(tmp_path)
    manifest_path = Path(settings_obj.embedding_metadata_path)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    before = '{"schema":"embedding_generation_manifest.v1","generation":{"id":"stable"}}'
    manifest_path.write_text(before, encoding="utf-8")

    original_dump = embedding_service.json.dump

    def _fail_dump(payload, handle, indent=None):
        if payload == {"schema": "embedding_generation_manifest.v1"}:
            raise OSError("write failed")
        return original_dump(payload, handle, indent=indent)

    monkeypatch.setattr(embedding_service.json, "dump", _fail_dump)
    with pytest.raises(OSError, match="write failed"):
        embedding_service._atomic_write_json(manifest_path, {"schema": "embedding_generation_manifest.v1"})

    assert manifest_path.read_text(encoding="utf-8") == before
    assert list(manifest_path.parent.glob(".embedding_metadata.json.tmp-*")) == []
