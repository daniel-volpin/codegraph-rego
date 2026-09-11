from __future__ import annotations

import hashlib

import pytest

from codegraph.policy.runtime.bundles import build_evidence_bundle


@pytest.fixture
def captured_source(tmp_path):
    prefix = b"class Example { "
    method = b'void hash() { MessageDigest.getInstance("MD5"); }'
    raw = prefix + method + b" }\n"
    path = tmp_path / "Example.java"
    path.write_bytes(raw)
    snapshot = {
        "signature": "Example.hash()",
        "name": "hash",
        "file_path": str(path),
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "range_status": "verified",
        "start_byte": len(prefix),
        "end_byte": len(prefix) + len(method),
    }
    return path, snapshot, method.decode()


def test_policy_evidence_reads_only_captured_verified_bytes(captured_source):
    _, snapshot, method = captured_source
    bundle = build_evidence_bundle(snapshot)
    assert bundle["source_code_raw"] == method
    assert bundle["parser"]["source_sha256"] == snapshot["source_sha256"]


def test_policy_evidence_refuses_same_length_source_drift(captured_source):
    path, snapshot, _ = captured_source
    path.write_bytes(path.read_bytes().replace(b"MD5", b"MD4"))
    with pytest.raises(ValueError, match="source.*hash"):
        build_evidence_bundle(snapshot)


@pytest.mark.parametrize(
    "changes",
    [
        {"source_sha256": None},
        {"range_status": "unverified"},
        {"start_byte": None},
        {"start_byte": -1},
        {"start_byte": True},
        {"end_byte": 10000},
    ],
)
def test_invalid_source_metadata_cannot_become_an_empty_successful_bundle(captured_source, changes):
    _, snapshot, _ = captured_source
    with pytest.raises(ValueError):
        build_evidence_bundle(snapshot | changes)


def test_missing_source_file_is_not_empty_successful_evidence(captured_source):
    path, snapshot, _ = captured_source
    path.unlink()
    with pytest.raises(ValueError, match="source.*unavailable"):
        build_evidence_bundle(snapshot)


def test_explicit_absent_declaration_range_remains_a_graph_only_fact(captured_source):
    _, snapshot, _ = captured_source
    bundle = build_evidence_bundle(snapshot | {"range_status": "absent", "start_byte": None, "end_byte": None})
    assert bundle["source_code_raw"] == ""


def test_single_method_evaluation_preserves_key_and_human_display(captured_source, monkeypatch):
    from codegraph.policy import integration

    _, snapshot, _ = captured_source
    method_key = "workspace@revision:Example.java#file:Example.java#method:hash/0"
    snapshot["method_key"] = method_key
    monkeypatch.setattr(integration, "shared_neo4j_driver", lambda: object())
    monkeypatch.setattr(
        integration.runtime_bundles,
        "fetch_method_snapshot",
        lambda _driver, key: snapshot if key == method_key else None,
    )
    monkeypatch.setattr(integration.runtime_bundles, "load_hybrid_search", lambda: None)
    monkeypatch.setattr(
        integration.runtime_opa,
        "evaluate_bundle",
        lambda _bundle: [{"violation_id": "ISO-A.10-WEAK-HASH"}],
    )
    evaluator = integration.PolicyEvaluator()
    result = evaluator.evaluate(method_key)
    assert result["method_key"] == method_key
    assert result["target_method"] == "Example.hash()"
    assert result["violations"][0]["evidence"]["source_sha256"] == snapshot["source_sha256"]

    missing = evaluator.evaluate("workspace@stale:Example.java#method:hash/0")
    assert missing["method_key"] == "workspace@stale:Example.java#method:hash/0"
    assert missing["error"] == "method_not_found"
