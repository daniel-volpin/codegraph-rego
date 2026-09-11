from __future__ import annotations

import pytest

from codegraph.ingestion.snapshots import (
    AmbiguousMethodError,
    SharedLineReplacementError,
    StaleSourceError,
    create_source_snapshot_from_bytes,
    sha256_hex,
)

OVERLOADS = b"""package demo;\r
class Sample {\r
  Sample(String... names) {\r
  }\r
\r
  void over(int[] xs) {\r
  }\r
\r
  void over(String... xs) {\r
  }\r
}\r
"""


def test_snapshot_identity_distinguishes_arrays_varargs_and_constructors() -> None:
    snapshot = create_source_snapshot_from_bytes(
        workspace_root="/workspace",
        source_path="/workspace/src/Sample.java",
        source_bytes=OVERLOADS,
        method_selector="demo.Sample#over(String...)",
        expected_source_sha256=sha256_hex(OVERLOADS),
    )

    assert snapshot.identity.declaring_type == "demo.Sample"
    assert snapshot.identity.name == "over"
    assert snapshot.identity.parameters[0].type_name == "String"
    assert snapshot.identity.parameters[0].varargs is True
    assert snapshot.identity.parameters[0].array_dimensions == 0
    assert snapshot.identity.selector == "demo.Sample#over(String...)"
    assert snapshot.file_sha256 == sha256_hex(OVERLOADS)
    assert snapshot.full_file_bytes == OVERLOADS
    assert "\r\n" in snapshot.full_file_text

    ctor = create_source_snapshot_from_bytes(
        workspace_root="/workspace",
        source_path="/workspace/src/Sample.java",
        source_bytes=OVERLOADS,
        method_selector="demo.Sample#Sample(String...)",
        expected_source_sha256=sha256_hex(OVERLOADS),
    )
    assert ctor.identity.is_constructor is True


def test_snapshot_preserves_qualified_parameter_type_chain() -> None:
    source = b"""package demo;
class Demo {
  @Deprecated
  void take(java.lang.String value) {
  }
}
"""

    snapshot = create_source_snapshot_from_bytes(
        workspace_root="/workspace",
        source_path="/workspace/Demo.java",
        source_bytes=source,
        method_selector="demo.Demo#take(java.lang.String)",
        expected_source_sha256=sha256_hex(source),
    )

    assert snapshot.identity.parameters[0].type_name == "java.lang.String"
    assert snapshot.identity.selector == "demo.Demo#take(java.lang.String)"
    assert snapshot.annotations == ("Deprecated",)


def test_snapshot_supports_bodyless_declaration_without_absorbing_neighbor() -> None:
    source = b"""package demo;
interface Demo {
  void absent();
  default void neighbor() {
  }
}
"""

    snapshot = create_source_snapshot_from_bytes(
        workspace_root="/workspace",
        source_path="/workspace/Demo.java",
        source_bytes=source,
        method_selector="demo.Demo#absent()",
        expected_source_sha256=sha256_hex(source),
    )

    assert snapshot.method_source == "  void absent();\n"
    assert "neighbor" not in snapshot.method_source


def test_snapshot_refuses_ambiguous_legacy_selector_and_stale_hash() -> None:
    with pytest.raises(AmbiguousMethodError):
        create_source_snapshot_from_bytes(
            workspace_root="/workspace",
            source_path="/workspace/src/Sample.java",
            source_bytes=OVERLOADS,
            method_selector="demo.Sample.over()",
            expected_source_sha256=sha256_hex(OVERLOADS),
        )

    with pytest.raises(StaleSourceError):
        create_source_snapshot_from_bytes(
            workspace_root="/workspace",
            source_path="/workspace/src/Sample.java",
            source_bytes=OVERLOADS,
            method_selector="demo.Sample#over(int[])",
            expected_source_sha256="0" * 64,
        )


def test_snapshot_refuses_unsafe_shared_line_replacement() -> None:
    source = b"package demo;\nclass Shared { void a() {} void b() {}\n}\n"

    with pytest.raises(SharedLineReplacementError):
        create_source_snapshot_from_bytes(
            workspace_root="/workspace",
            source_path="/workspace/Shared.java",
            source_bytes=source,
            method_selector="demo.Shared#a()",
            expected_source_sha256=sha256_hex(source),
        )
