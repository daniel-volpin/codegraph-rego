from __future__ import annotations

import pytest

from codegraph.ingestion.snapshots import create_source_snapshot_from_bytes, sha256_hex
from codegraph.remediation.candidate import InvalidCandidateError, build_candidate_overlay

BASE = b"""package demo;\r
class Crypto {\r
  int keep = 1;\r
\r
  public void hash() {\r
    java.security.MessageDigest.getInstance("MD5");\r
  }\r
\r
  void untouched() {}\r
}\r
"""


def test_candidate_overlay_preserves_surrounding_bytes_and_uses_crlf() -> None:
    snapshot = create_source_snapshot_from_bytes(
        workspace_root="/workspace",
        source_path="/workspace/src/Crypto.java",
        source_bytes=BASE,
        method_selector="demo.Crypto#hash()",
        expected_source_sha256=sha256_hex(BASE),
    )

    overlay = build_candidate_overlay(
        snapshot,
        b"""  public void hash() {
    java.security.MessageDigest.getInstance("SHA-256");
  }""",
    )

    before, _, rest = BASE.partition(b"  public void hash()")
    _, _, after = rest.partition(b"\r\n  }\r\n")
    assert overlay.candidate_file_bytes.startswith(before)
    assert overlay.candidate_file_bytes.endswith(after)
    assert b"SHA-256" in overlay.candidate_file_bytes
    assert b"\r\n    java.security.MessageDigest" in overlay.candidate_file_bytes
    assert b"{\n    java.security.MessageDigest" not in overlay.candidate_file_bytes
    assert overlay.candidate_method_sha256 == sha256_hex(overlay.candidate_method_bytes)


def test_candidate_overlay_rejects_malformed_or_identity_changing_candidate() -> None:
    snapshot = create_source_snapshot_from_bytes(
        workspace_root="/workspace",
        source_path="/workspace/src/Crypto.java",
        source_bytes=BASE,
        method_selector="demo.Crypto#hash()",
        expected_source_sha256=sha256_hex(BASE),
    )

    with pytest.raises(InvalidCandidateError):
        build_candidate_overlay(snapshot, b"public void different() {}")

    with pytest.raises(InvalidCandidateError):
        build_candidate_overlay(snapshot, b'public void hash() { String s = "unterminated\n; }')


def test_candidate_overlay_rejects_added_member_declarations() -> None:
    source = b"""package demo;
class Demo {
  void hash() {
  }
}
"""
    snapshot = create_source_snapshot_from_bytes(
        workspace_root="/workspace",
        source_path="/workspace/Demo.java",
        source_bytes=source,
        method_selector="demo.Demo#hash()",
        expected_source_sha256=sha256_hex(source),
    )

    with pytest.raises(InvalidCandidateError, match="expected_exactly_one_method_declaration"):
        build_candidate_overlay(snapshot, b"  void hash() {}\n  void extra() {}\n")
