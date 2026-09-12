"""Semantic parity between canonical evaluation and remediation preview.

The remediation preview evaluates a candidate method through
``build_virtual_bundle``, which must delegate to the same canonical evidence
core (``build_evidence_bundle_from_source``) as the on-disk path. These tests
pin that contract: for the same source text and graph context, both paths
must produce identical OPA verdicts.

Historical context: the pre-unification preview bundle fed Rego the *raw*
candidate source (comments/string literals included) and omitted
``analysis_flags`` entirely, producing false FAILs on insecure-looking text
inside comments and false PASSes on rules that fire via computed flags. The
``comment_only`` and ``flag_dependent_sql`` fixtures fail against that
implementation.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from codegraph.java.fragments import parse_source_file
from codegraph.policy.runtime.bundles import build_evidence_bundle
from codegraph.policy.runtime.opa import evaluate_bundle
from codegraph.remediation.context import build_virtual_graph_context
from codegraph.remediation.verification import build_virtual_bundle

SIGNATURE = "org.owasp.benchmark.testcode.BenchmarkTest99001.doPost(HttpServletRequest,HttpServletResponse)"
CLASS_FQN = "org.owasp.benchmark.testcode.BenchmarkTest99001"

COMMENT_ONLY_MD5 = """public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    // legacy code used java.security.MessageDigest.getInstance("MD5") here
    java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
    md.update(request.getParameter("input").getBytes());
}"""

FLAG_DEPENDENT_SQL = """public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String param = request.getParameter("id");
    String sql = "SELECT * FROM users WHERE id = '" + param + "'";
    java.sql.Statement stmt = connection.createStatement();
    java.sql.ResultSet rs = stmt.executeQuery(sql);
}"""

SAFE_SHA256 = """public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
    md.update(request.getParameter("input").getBytes());
}"""

STILL_VULNERABLE_MD5 = """public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
    md.update(request.getParameter("input").getBytes());
}"""


def _violation_ids(violations: list[dict]) -> set[str]:
    return {str(v.get("violation_id")) for v in violations}


def _snapshot(file_path: str, virtual_graph: dict) -> dict:
    raw = Path(file_path).read_bytes()
    parsed = parse_source_file(raw, relative_path=Path(file_path).name, resolve_bindings=False)
    method = next(method for method in parsed.methods if method.name == "doPost")
    return {
        "method_key": f"workspace@revision:{parsed.relative_path}#{method.source_key}",
        "signature": SIGNATURE,
        "name": "doPost",
        "class_fqn": CLASS_FQN,
        "file_path": file_path,
        "start_line": method.declaration_range.start_line,
        "end_line": method.declaration_range.end_line,
        "start_byte": method.declaration_range.start_byte,
        "end_byte": method.declaration_range.end_byte,
        "range_status": method.declaration_range.status,
        "source_sha256": parsed.source_sha256,
        "modifiers": ["public"],
        "annotations": virtual_graph["annotations"],
        "uses_fields": virtual_graph["uses_fields"],
        "calls": virtual_graph["calls"],
        "callers": virtual_graph["callers"],
    }


def _canonical_violation_ids(source: str, tmp_path: Path) -> set[str]:
    """On-disk path: method source in a real file, canonical evidence bundle."""
    java_file = tmp_path / "BenchmarkTest99001.java"
    java_file.write_text(
        "package org.owasp.benchmark.testcode;\nclass BenchmarkTest99001 {\n" + source + "\n}\n",
        encoding="utf-8",
    )
    virtual_graph = build_virtual_graph_context(source, base_graph={})
    bundle = build_evidence_bundle(_snapshot(java_file.as_posix(), virtual_graph))
    return _violation_ids(evaluate_bundle(bundle))


def _preview_context(source: str, file_path: str = "src/main/java/Missing.java") -> dict:
    return {
        "target_method": SIGNATURE,
        "file_path": file_path,
        "violation": {"class_fqn": CLASS_FQN, "modifiers": ["public"]},
        "evidence": {
            "start_line": 1,
            "end_line": len(source.splitlines()),
            "vector_context": [],
        },
    }


def _preview_violation_ids(source: str) -> set[str]:
    """Virtual path: candidate source in memory, preview bundle."""
    virtual_graph = build_virtual_graph_context(source, base_graph={})
    bundle = build_virtual_bundle(_preview_context(source), source, virtual_graph)
    return _violation_ids(evaluate_bundle(bundle))


@pytest.mark.requires_opa
@pytest.mark.parametrize(
    ("source", "expected_ids"),
    [
        # Lexical-noise parity: insecure text only inside a comment must not
        # trip substring rules. The old preview raw-source bundle flagged
        # ISO-A.10-WEAK-HASH here (false FAIL).
        pytest.param(COMMENT_ONLY_MD5, set(), id="comment_only_md5"),
        # Analysis-flag parity: this rule fires only via computed
        # analysis_flags. The old preview bundle omitted the flags and
        # reported no violation (false PASS).
        pytest.param(FLAG_DEPENDENT_SQL, {"ISO-A.8-SQL-INJECTION"}, id="flag_dependent_sql"),
        # A correctly remediated candidate passes through both paths.
        pytest.param(SAFE_SHA256, set(), id="safe_sha256"),
        # A still-vulnerable candidate fails through both paths.
        pytest.param(STILL_VULNERABLE_MD5, {"ISO-A.10-WEAK-HASH"}, id="still_vulnerable_md5"),
    ],
)
def test_preview_matches_canonical_evaluation(source, expected_ids, tmp_path) -> None:
    canonical_ids = _canonical_violation_ids(source, tmp_path)
    preview_ids = _preview_violation_ids(source)

    assert canonical_ids == preview_ids, "preview diverged from canonical evaluation"
    assert canonical_ids == expected_ids, "unexpected canonical verdict"


@pytest.mark.requires_opa
def test_preview_is_read_only(tmp_path, monkeypatch) -> None:
    """Preview bundle construction and evaluation must not touch the
    workspace file, the Neo4j graph, or the ingestion pipeline."""
    java_file = tmp_path / "BenchmarkTest99001.java"
    java_file.write_text(STILL_VULNERABLE_MD5, encoding="utf-8")
    original_bytes = java_file.read_bytes()

    import codegraph.db as db

    def _forbidden(*_args, **_kwargs):
        raise AssertionError("preview must not touch the graph or ingestion pipeline")

    monkeypatch.setattr(db, "get_neo4j_driver", _forbidden)
    monkeypatch.setattr(db, "shared_neo4j_driver", _forbidden)

    source = STILL_VULNERABLE_MD5
    virtual_graph = build_virtual_graph_context(source, base_graph={})
    context = _preview_context(source, file_path=java_file.as_posix())
    bundle = build_virtual_bundle(context, source, virtual_graph)
    violations = evaluate_bundle(bundle)

    assert _violation_ids(violations) == {"ISO-A.10-WEAK-HASH"}
    assert java_file.read_bytes() == original_bytes


def test_virtual_bundle_carries_canonical_policy_input_fields() -> None:
    """The shared core must emit every input field the active Rego policies
    read (input.source_code, target_method, method_name, graph_context,
    analysis_flags) plus the evidence fields downstream
    consumers rely on."""
    source = FLAG_DEPENDENT_SQL
    virtual_graph = build_virtual_graph_context(source, base_graph={})
    bundle = build_virtual_bundle(_preview_context(source), source, virtual_graph)

    required = {
        "target_method",
        "method_name",
        "source_code",
        "source_code_raw",
        "graph_context",
        "analysis_flags",
        "helper_summaries",
        "vector_context",
    }
    assert required <= set(bundle), f"missing policy-input fields: {sorted(required - set(bundle))}"
    assert set(bundle["graph_context"]) >= {"annotations", "uses_fields", "calls", "callers"}
    # The lexically active view drives the flags; the raw candidate remains
    # available for human-facing evidence.
    assert bundle["analysis_flags"]["sql_dynamic_query_detected"] is True
    assert bundle["analysis_flags"]["sql_query_uses_tainted_input"] is True
    assert bundle["source_code_raw"] == source
    # Rego sees the substring-safe view, never raw string-literal text.
    assert "SELECT * FROM users" not in bundle["source_code"]
