from __future__ import annotations

from dataclasses import dataclass

import javalang
from javalang.tokenizer import LexerError
from javalang.tree import MethodDeclaration

from codegraph.ingestion.snapshots import SnapshotError, SourceSnapshot, create_source_snapshot_from_bytes, sha256_hex


class InvalidCandidateError(ValueError):
    """Raised when a candidate replacement is malformed or changes identity."""


@dataclass(frozen=True)
class CandidateOverlay:
    baseline: SourceSnapshot
    candidate_method_bytes: bytes
    candidate_method_source: str
    candidate_file_bytes: bytes
    candidate_file_source: str
    candidate_method_sha256: str
    candidate_file_sha256: str
    candidate_snapshot: SourceSnapshot


def _decode_candidate(candidate_method_bytes: bytes) -> str:
    try:
        return candidate_method_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InvalidCandidateError(f"invalid_candidate_encoding: {exc}") from exc


def _replacement_bytes(candidate_method_source: str, newline: str, include_final_newline: bool) -> bytes:
    lines = candidate_method_source.splitlines()
    text = newline.join(lines)
    if include_final_newline:
        text += newline
    return text.encode("utf-8")


def _assert_exactly_one_method_declaration(candidate_method_source: str, baseline: SourceSnapshot) -> None:
    if baseline.identity.is_constructor:
        raise InvalidCandidateError("constructor_candidate_overlay_unsupported")
    try:
        tree = javalang.parse.parse(f"class CandidateReplacement {{\n{candidate_method_source}\n}}")
    except (javalang.parser.JavaSyntaxError, LexerError, IndexError, TypeError) as exc:
        raise InvalidCandidateError(f"invalid_candidate_syntax: {exc.__class__.__name__}") from exc
    types = getattr(tree, "types", []) or []
    if len(types) != 1:
        raise InvalidCandidateError("expected_exactly_one_method_declaration")
    body = getattr(types[0], "body", []) or []
    methods = [node for node in body if isinstance(node, MethodDeclaration)]
    if len(body) != 1 or len(methods) != 1:
        raise InvalidCandidateError("expected_exactly_one_method_declaration")


def build_candidate_overlay(
    baseline: SourceSnapshot,
    candidate_method_bytes: bytes,
) -> CandidateOverlay:
    candidate_method_source = _decode_candidate(candidate_method_bytes)
    _assert_exactly_one_method_declaration(candidate_method_source, baseline)
    lines = baseline.full_file_bytes.splitlines(keepends=True)
    replaced = lines[baseline.start_line - 1 : baseline.end_line]
    include_final_newline = bool(replaced and (replaced[-1].endswith(b"\n") or replaced[-1].endswith(b"\r\n")))
    replacement = _replacement_bytes(candidate_method_source, baseline.newline, include_final_newline)
    candidate_file_bytes = b"".join(lines[: baseline.start_line - 1]) + replacement + b"".join(lines[baseline.end_line :])
    try:
        candidate_snapshot = create_source_snapshot_from_bytes(
            workspace_root=baseline.workspace_root,
            source_path=baseline.source_path,
            source_bytes=candidate_file_bytes,
            method_selector=baseline.identity.selector,
            expected_source_sha256=sha256_hex(candidate_file_bytes),
        )
    except SnapshotError as exc:
        raise InvalidCandidateError(str(exc)) from exc
    if (
        candidate_snapshot.identity.declaring_type != baseline.identity.declaring_type
        or candidate_snapshot.identity.name != baseline.identity.name
        or candidate_snapshot.identity.parameters != baseline.identity.parameters
        or candidate_snapshot.identity.is_constructor != baseline.identity.is_constructor
    ):
        raise InvalidCandidateError("candidate_identity_mismatch")
    return CandidateOverlay(
        baseline=baseline,
        candidate_method_bytes=candidate_snapshot.method_bytes,
        candidate_method_source=candidate_snapshot.method_source,
        candidate_file_bytes=candidate_file_bytes,
        candidate_file_source=candidate_file_bytes.decode("utf-8"),
        candidate_method_sha256=candidate_snapshot.method_sha256,
        candidate_file_sha256=sha256_hex(candidate_file_bytes),
        candidate_snapshot=candidate_snapshot,
    )
