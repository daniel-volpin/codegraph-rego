from __future__ import annotations

from pathlib import Path

import pytest

from codegraph.ingestion.snapshots import (
    create_source_snapshot_from_bytes,
    sha256_hex,
)
from codegraph.remediation.candidate import InvalidCandidateError, build_candidate_overlay
from codegraph.remediation.context import build_virtual_graph_context
from codegraph.remediation.editing import extract_method_span, validate_method_shape
from codegraph.remediation.planning import build_remediation_plan, validate_remediation_plan

OWNED_FILES = (
    Path("codegraph/ingestion/snapshots.py"),
    Path("codegraph/remediation/candidate.py"),
    Path("codegraph/remediation/editing.py"),
    Path("codegraph/remediation/context.py"),
    Path("codegraph/remediation/planning.py"),
)
LEGACY_PARSER_TOKEN = "java" + "lang"


def test_owned_parser_cutover_removes_legacy_parser_imports_and_signature_output() -> None:
    for path in OWNED_FILES:
        text = path.read_text(encoding="utf-8")
        assert LEGACY_PARSER_TOKEN not in text
    assert "legacy_signature" not in Path("codegraph/ingestion/snapshots.py").read_text(encoding="utf-8")


def test_snapshot_uses_jdt_verified_byte_ranges_for_modern_shapes_and_crlf_unicode() -> None:
    source = (
        "package demo;\r\n"
        "record Demo(String name) {\r\n"
        "  @Deprecated\r\n"
        "  public void take(java.lang.String[] values, int... counts) {\r\n"
        "    String text = \"brace } and snowman ☃\"; // comment { ignored\r\n"
        "  }\r\n"
        "}\r\n"
    ).encode()

    snapshot = create_source_snapshot_from_bytes(
        workspace_root="/workspace",
        source_path="/workspace/src/Demo.java",
        source_bytes=source,
        method_selector="demo.Demo#take(java.lang.String[],int...)",
        expected_source_sha256=sha256_hex(source),
    )

    assert snapshot.identity.selector == "demo.Demo#take(java.lang.String[],int...)"
    assert snapshot.identity.canonical_key.endswith("#" + snapshot.identity.source_key)
    assert snapshot.identity.parameters[0].type_name == "java.lang.String"
    assert snapshot.identity.parameters[0].array_dimensions == 1
    assert snapshot.identity.parameters[1].type_name == "int"
    assert snapshot.identity.parameters[1].varargs is True
    assert snapshot.method_bytes == source[snapshot.start_byte : snapshot.end_byte]
    assert b"snowman \xe2\x98\x83" in snapshot.method_bytes
    assert snapshot.annotations == ("Deprecated",)


def test_snapshot_supports_same_line_and_bodyless_ranges_without_neighbor_absorption() -> None:
    bodyless_source = b"package demo;\ninterface Demo { void absent(); default void neighbor(){} }\n"
    bodyless = create_source_snapshot_from_bytes(
        workspace_root="/workspace",
        source_path="/workspace/Demo.java",
        source_bytes=bodyless_source,
        method_selector="demo.Demo#absent()",
        expected_source_sha256=sha256_hex(bodyless_source),
    )
    assert bodyless.method_source == "void absent();"
    assert "neighbor" not in bodyless.method_source

    same_line = b"package demo;\nclass Demo { void a(){} void b(){} }\n"
    snapshot = create_source_snapshot_from_bytes(
        workspace_root="/workspace",
        source_path="/workspace/Demo.java",
        source_bytes=same_line,
        method_selector="demo.Demo#a()",
        expected_source_sha256=sha256_hex(same_line),
    )
    assert snapshot.method_bytes == b"void a(){}"


def test_candidate_overlay_rejects_extra_root_members_but_allows_method_local_types() -> None:
    source = b"package demo;\nclass Demo { void hash(){ } }\n"
    snapshot = create_source_snapshot_from_bytes(
        workspace_root="/workspace",
        source_path="/workspace/Demo.java",
        source_bytes=source,
        method_selector="demo.Demo#hash()",
        expected_source_sha256=sha256_hex(source),
    )

    with pytest.raises(InvalidCandidateError, match="expected_exactly_one_method_declaration"):
        build_candidate_overlay(snapshot, b"void hash(){}\nint injected = 0;\n")
    with pytest.raises(InvalidCandidateError, match="expected_exactly_one_method_declaration"):
        build_candidate_overlay(snapshot, b"void hash(){}\nclass Injected {}\n")

    overlay = build_candidate_overlay(snapshot, b"void hash(){ class Local { } new Local(); }")
    assert overlay.candidate_file_bytes.startswith(b"package demo;\nclass Demo { ")
    assert overlay.candidate_file_bytes.endswith(b" }\n")
    assert b"class Local" in overlay.candidate_method_bytes


def test_candidate_overlay_reparses_whole_file_and_refuses_identity_change() -> None:
    source = b"package demo;\nclass Demo { void take(java.lang.String value){} }\n"
    snapshot = create_source_snapshot_from_bytes(
        workspace_root="/workspace",
        source_path="/workspace/Demo.java",
        source_bytes=source,
        method_selector="demo.Demo#take(java.lang.String)",
        expected_source_sha256=sha256_hex(source),
    )

    with pytest.raises(InvalidCandidateError, match="candidate_identity_mismatch"):
        build_candidate_overlay(snapshot, b"void take(java.lang.Integer value){}")


@pytest.mark.parametrize("snippet", ["void absent();", "class NotMethod {}", "int field = 0;"])
def test_validate_method_shape_refuses_non_body_method_fragments(snippet: str) -> None:
    with pytest.raises(ValueError):
        validate_method_shape([snippet], "demo.Demo#hash()")


def test_validate_method_shape_accepts_java_text_blocks() -> None:
    validate_method_shape(
        [
            "void render() {",
            '  String html = """',
            "      <p>safe</p>",
            '      """;',
            "}",
        ],
        "demo.Demo#render()",
    )


def test_editing_replaces_exact_same_line_method_bytes_without_name_only_ambiguity() -> None:
    source = "package demo;\nclass Demo { void a(){} void b(){} }\n"
    baseline = create_source_snapshot_from_bytes(
        workspace_root="/workspace",
        source_path="/workspace/Demo.java",
        source_bytes=source.encode("utf-8"),
        method_selector="demo.Demo#a()",
        expected_source_sha256=sha256_hex(source),
    )
    overlay = build_candidate_overlay(baseline, b"void a(){\n  int x = 1;\n}")
    assert baseline.method_source == "void a(){}"
    assert overlay.candidate_method_source == "void a(){\n  int x = 1;\n}"
    assert "void b(){}" in overlay.candidate_file_source
    with pytest.raises(ValueError, match="invalid_method_selector|ambiguous_method_selector|method_selector_not_found"):
        extract_method_span(source, "a()")


def test_context_uses_jdt_observations_and_marks_unresolved_explicitly() -> None:
    source = """@Deprecated
public void hash() {
  this.logger.info("x");
  missing.call(1);
}
"""
    graph = build_virtual_graph_context(source, base_graph={})
    assert "Deprecated" in graph["annotations"]
    assert any(call["name"] == "info" and call["terminal_chain_member"] is True for call in graph["observed_calls"])
    assert any(call["resolution_status"] == "unresolved" for call in graph["observed_calls"])
    assert "this.logger.info" in graph["calls"]
    assert any(field["name"] == "logger" for field in graph["uses_fields"])


def test_planning_uses_jdt_terminal_chain_members_for_invariants() -> None:
    plan = build_remediation_plan(
        """public byte[] hash(byte[] input) throws Exception {
    return java.security.MessageDigest.getInstance("MD5").digest(input);
}
"""
    )
    assert plan.transformation_class == "receiver_chain_upgrade"
    assert [(c.member, c.arg_count, c.source_kind) for c in plan.terminal_invocation_contracts] == [
        ("digest", 1, "factory_chain")
    ]
    assert (
        validate_remediation_plan(plan, "public byte[] hash(byte[] input) throws Exception { return input; }")
        == "plan_invariant_violation: missing_terminal_invocation:digest/1"
    )
