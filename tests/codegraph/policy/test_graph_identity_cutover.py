import pytest

from codegraph.policy.runtime.bundles import (
    fetch_method_snapshot,
    fetch_methods_with_context,
    validate_graph_generation,
)
from codegraph.search.hybrid import fetch_graph_context_for_method


class _Result:
    def __init__(self, records):
        self._records = records

    def __iter__(self):
        return iter(self._records)

    def single(self):
        return self._records[0] if self._records else None


class _Session:
    def __init__(self, records):
        self.records = records
        self.queries: list[tuple[str, dict]] = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def run(self, cypher, parameters=None, **kwargs):
        params = dict(parameters or {})
        params.update(kwargs)
        self.queries.append((cypher, params))
        if "incompatible_count" in cypher:
            return _Result([{"incompatible_count": 0}])
        return _Result(self.records)


class _Driver:
    def __init__(self, records):
        self.session_obj = _Session(records)

    def session(self):
        return self.session_obj


def _record(method_key: str = "workspace@revision:Demo.java#method:a") -> dict:
    return {
        "method_key": method_key,
        "signature": "com.acme.Demo.a(java.lang.String)",
        "name": "a",
        "class_fqn": "com.acme.Demo",
        "declaring_type_key": "workspace@revision:Demo.java#type:Demo",
        "file_path": "/workspace/src/main/java/com/acme/Demo.java",
        "relative_path": "src/main/java/com/acme/Demo.java",
        "start_line": 3,
        "end_line": 5,
        "start_byte": 20,
        "end_byte": 80,
        "modifiers": ["public"],
        "property_annotations": ["Override"],
        "annotation_nodes": ["Transactional"],
        "uses_fields": [{"name": "logger", "field_key": "field:logger"}],
        "calls": ["workspace@revision:Demo.java#method:b"],
        "call_evidence": [{"source_key": "call:external", "resolution_status": "unresolved"}],
        "callers": ["workspace@revision:Demo.java#method:c"],
        "workspace_id": "workspace",
        "revision_id": "revision",
        "parser_backend": "eclipse-jdt",
        "parser_version": "3.47.0",
        "source_sha256": "f" * 64,
        "range_status": "verified",
    }


def test_policy_snapshots_are_keyed_by_method_key_without_signature_fallbacks() -> None:
    driver = _Driver([_record()])

    snap = fetch_method_snapshot(driver, "workspace@revision:Demo.java#method:a")

    assert snap is not None
    assert snap["method_key"] == "workspace@revision:Demo.java#method:a"
    assert snap["signature"] == "com.acme.Demo.a(java.lang.String)"
    assert snap["calls"] == ["workspace@revision:Demo.java#method:b"]
    query = driver.session_obj.queries[-1][0]
    assert "m.method_key = $method_key" in query
    assert "coalesce" not in query.lower()
    assert " OR " not in query


def test_policy_snapshot_fetch_refuses_legacy_method_nodes() -> None:
    class _LegacySession(_Session):
        def run(self, cypher, parameters=None, **kwargs):
            self.queries.append((cypher, dict(parameters or {}, **kwargs)))
            if "incompatible_count" in cypher:
                return _Result([{"incompatible_count": 2}])
            return _Result([])

    class _LegacyDriver(_Driver):
        def __init__(self):
            self.session_obj = _LegacySession([])

    with pytest.raises(RuntimeError, match="explicit rebuild"):
        fetch_methods_with_context(_LegacyDriver())


def test_search_graph_context_uses_method_key_only() -> None:
    driver = _Driver([{"method": "display", "neighbors": [{"type": "Method", "id": "method-key-b"}]}])

    result = fetch_graph_context_for_method("workspace@revision:Demo.java#method:a", driver)

    assert result == [{"method": "display", "neighbors": [{"type": "Method", "id": "method-key-b"}]}]
    query = driver.session_obj.queries[-1][0]
    assert "m.method_key = $method_key" in query
    assert "coalesce" not in query.lower()
    assert " OR " not in query


def test_validate_graph_generation_refuses_incompatible_method_nodes() -> None:
    class _BadSession(_Session):
        def run(self, cypher, parameters=None, **kwargs):
            self.queries.append((cypher, dict(parameters or {}, **kwargs)))
            if "incompatible_count" in cypher:
                return _Result([{"incompatible_count": 1}])
            return _Result([])

    class _BadDriver(_Driver):
        def __init__(self):
            self.session_obj = _BadSession([])

    with pytest.raises(RuntimeError, match="explicit rebuild"):
        validate_graph_generation(_BadDriver())


def test_validate_graph_generation_returns_schema_metadata() -> None:
    class _GenerationSession(_Session):
        def run(self, cypher, parameters=None, **kwargs):
            self.queries.append((cypher, dict(parameters or {}, **kwargs)))
            if "incompatible_count" in cypher:
                return _Result([{"incompatible_count": 0}])
            return _Result(
                [
                    {
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
                ]
            )

    driver = _Driver([])
    driver.session_obj = _GenerationSession([])

    metadata = validate_graph_generation(driver)

    assert metadata == {
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
