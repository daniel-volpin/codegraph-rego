from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from codegraph.embedding import service as embedding_service

_GRAPH_GENERATION = {
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
        lambda: [embedding_service._MethodSnippet(method_key="key:A#a", display_signature="pkg.A#a()", code="class A {}")],
    )
    monkeypatch.setattr(embedding_service, "_fetch_active_graph_generation", lambda: _GRAPH_GENERATION)
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
    assert generation["graph_generation"] == _GRAPH_GENERATION
    metadata = generation["metadata"]
    for key in ("index_path", "signature_map_path", "metadata_path"):
        assert Path(metadata[key]).is_file()  # type: ignore[name-defined]
    for key in ("index_sha256", "signature_map_sha256", "metadata_sha256"):
        assert len(metadata[key]) == 64
    assert not Path(settings_obj.signature_map_path_full).exists()
    assert not Path(settings_obj.signature_map_path).exists()


def test_build_embeddings_allows_implicit_constructor_but_indexes_only_verified_source_methods(tmp_path, monkeypatch) -> None:
    settings_obj = _make_settings(tmp_path)
    monkeypatch.setattr(embedding_service, "settings", settings_obj)
    monkeypatch.setattr(
        embedding_service,
        "_fetch_method_snippets",
        lambda: [
            embedding_service._MethodSnippet(
                method_key="workspace@revision:A.java#method:real",
                display_signature="A.real()",
                code="void real() {}",
            )
        ],
    )
    monkeypatch.setattr(embedding_service, "_fetch_active_graph_generation", lambda: _GRAPH_GENERATION)
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

    manifest = json.loads((tmp_path / "index" / "embedding_metadata.json").read_text(encoding="utf-8"))
    assert manifest["generation"]["count"] == 1
    assert manifest["generation"]["graph_generation"]["method_count"] == 2
    assert manifest["generation"]["graph_generation"]["indexable_method_count"] == 1


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
        lambda: [embedding_service._MethodSnippet(method_key="key:A#a", display_signature="pkg.A#a()", code="class A1 {}")],
    )
    monkeypatch.setattr(embedding_service, "_fetch_active_graph_generation", lambda: _GRAPH_GENERATION)
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
        lambda: [embedding_service._MethodSnippet(method_key="key:A#a", display_signature="pkg.A#a()", code="class A2 {}")],
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
    assert results == ["key:A#a"]


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
    graph_generation = {**_GRAPH_GENERATION, "indexable_method_count": 2}
    graph_generation["active_revisions"] = [{**_GRAPH_GENERATION["active_revisions"][0], "indexable_method_count": 2}]
    monkeypatch.setattr(embedding_service, "settings", settings_obj)
    monkeypatch.setattr(
        embedding_service,
        "_fetch_method_snippets",
        lambda: [
            embedding_service._MethodSnippet(method_key="key:A#a", display_signature="pkg.A#a()", code="class A {}"),
            embedding_service._MethodSnippet(method_key="key:B#b", display_signature="pkg.B#b()", code="class B {}"),
        ],
    )
    monkeypatch.setattr(embedding_service, "_fetch_active_graph_generation", lambda: graph_generation)
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


def test_build_embeddings_rejects_when_snippets_do_not_cover_indexable_methods(tmp_path, monkeypatch) -> None:
    settings_obj = _make_settings(tmp_path)
    graph_generation = {**_GRAPH_GENERATION, "indexable_method_count": 2}
    graph_generation["active_revisions"] = [{**_GRAPH_GENERATION["active_revisions"][0], "indexable_method_count": 2}]
    monkeypatch.setattr(embedding_service, "settings", settings_obj)
    monkeypatch.setattr(
        embedding_service,
        "_fetch_method_snippets",
        lambda: [embedding_service._MethodSnippet(method_key="key:A#a", display_signature="pkg.A#a()", code="class A {}")],
    )
    monkeypatch.setattr(embedding_service, "_fetch_active_graph_generation", lambda: graph_generation)

    with pytest.raises(RuntimeError, match="indexable method"):
        embedding_service.EmbeddingService.build_embeddings()


def test_build_embeddings_rechecks_active_graph_generation_before_manifest_publish(tmp_path, monkeypatch) -> None:
    settings_obj = _make_settings(tmp_path)
    first = _GRAPH_GENERATION
    second = {**_GRAPH_GENERATION, "active_revisions": [{**_GRAPH_GENERATION["active_revisions"][0], "revision_id": "new"}]}
    generations = iter([first, second])
    monkeypatch.setattr(embedding_service, "settings", settings_obj)
    monkeypatch.setattr(
        embedding_service,
        "_fetch_method_snippets",
        lambda: [embedding_service._MethodSnippet(method_key="key:A#a", display_signature="pkg.A#a()", code="class A {}")],
    )
    monkeypatch.setattr(embedding_service, "_fetch_active_graph_generation", lambda: next(generations))
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
    monkeypatch.setattr(
        embedding_service,
        "_publish_generation_manifest",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("must not publish stale graph generation")),
    )

    with pytest.raises(RuntimeError, match="active graph generation changed"):
        embedding_service.EmbeddingService.build_embeddings()


def test_fetch_method_snippets_prefers_exact_ranges_for_overloads(tmp_path, monkeypatch) -> None:
    java_file = tmp_path / "Overloads.java"
    content = (
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
        + "\n"
    )
    java_file.write_text(content, encoding="utf-8")
    first_start = content.index("  void work()")
    first_end = content.index("  void work(int n)")
    second_start = first_end
    second_end = content.index("}", second_start) + 1

    rows = [
        {
            "method_key": "key:Overloads#work",
            "display_signature": "Overloads#work()",
            "path": str(java_file),
            "start_byte": first_start,
            "end_byte": first_end,
            "source_sha256": hashlib.sha256(java_file.read_bytes()).hexdigest(),
        },
        {
            "method_key": "key:Overloads#work-int",
            "display_signature": "Overloads#work(int)",
            "path": str(java_file),
            "start_byte": second_start,
            "end_byte": second_end,
            "source_sha256": hashlib.sha256(java_file.read_bytes()).hexdigest(),
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


def test_fetch_method_snippets_rejects_ambiguous_missing_range_fallback(tmp_path, monkeypatch) -> None:
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
    rows = [{"method_key": "key:Overloads#work", "display_signature": "Overloads#work()", "path": str(java_file), "start_byte": None, "end_byte": None}]

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
    with pytest.raises(RuntimeError, match="incomplete byte range metadata"):
        embedding_service._fetch_method_snippets()


def test_fetch_method_snippets_rejects_incomplete_range_without_fallback(tmp_path, monkeypatch) -> None:
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
    rows = [{"method_key": "key:Overloads#work", "display_signature": "Overloads#work()", "path": str(java_file), "start_byte": 2, "end_byte": None}]

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
    with pytest.raises(RuntimeError, match="incomplete byte range metadata"):
        embedding_service._fetch_method_snippets()


def test_fetch_method_snippets_rejects_out_of_file_range_without_fallback(tmp_path, monkeypatch) -> None:
    java_file = tmp_path / "Overloads.java"
    java_file.write_text("class Overloads {\n  void work() {}\n}\n", encoding="utf-8")
    rows = [{"method_key": "key:Overloads#work", "display_signature": "Overloads#work()", "path": str(java_file), "start_byte": 2, "end_byte": 2000}]

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
    with pytest.raises(RuntimeError, match="invalid byte range 2-2000"):
        embedding_service._fetch_method_snippets()


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
