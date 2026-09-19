from __future__ import annotations

from dataclasses import dataclass

from codegraph.ingestion.snapshots import SnapshotError, SourceSnapshot, create_source_snapshot_from_bytes, sha256_hex
from codegraph.java.fragments import JavaFragmentError, ParsedMethodFragment, parse_strict_method_fragment


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


def _assert_exactly_one_method_declaration(candidate_method_bytes: bytes) -> ParsedMethodFragment:
    try:
        return parse_strict_method_fragment(candidate_method_bytes, require_body=True)
    except JavaFragmentError as exc:
        raise InvalidCandidateError(str(exc)) from exc


def _method_bytes_with_baseline_newline(fragment: ParsedMethodFragment, baseline: SourceSnapshot) -> bytes:
    text = baseline.newline.join(fragment.method_source.splitlines())
    return text.encode("utf-8")


def build_candidate_overlay(
    baseline: SourceSnapshot,
    candidate_method_bytes: bytes,
) -> CandidateOverlay:
    _decode_candidate(candidate_method_bytes)
    candidate_fragment = _assert_exactly_one_method_declaration(candidate_method_bytes)
    if (
        candidate_fragment.method.name != baseline.identity.name
        or tuple(param.type.source or param.type.qualified_name or "" for param in candidate_fragment.method.parameters)
        != tuple(param.selector_text for param in baseline.identity.parameters)
        or (candidate_fragment.method.kind in {"constructor", "compact_constructor"})
        != baseline.identity.is_constructor
    ):
        raise InvalidCandidateError("candidate_identity_mismatch")
    normalized_method_bytes = _method_bytes_with_baseline_newline(candidate_fragment, baseline)
    candidate_file_bytes = (
        baseline.full_file_bytes[: baseline.start_byte]
        + normalized_method_bytes
        + baseline.full_file_bytes[baseline.end_byte :]
    )
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
