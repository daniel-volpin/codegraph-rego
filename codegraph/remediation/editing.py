from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from codegraph.config import settings
from codegraph.ingestion.snapshots import (
    AmbiguousMethodError,
    SnapshotError,
    create_source_snapshot_from_bytes,
    sha256_hex,
)
from codegraph.java.fragments import JavaFragmentError, parse_strict_method_fragment

_PROJECT_ROOT = Path(__file__).resolve().parents[2]


def detect_text_format(raw_bytes: bytes) -> tuple[str, str]:
    """Return ``(encoding, newline)`` for round-tripping a source file.

    ``encoding`` is ``"utf-8-sig"`` when a UTF-8 BOM is present so a
    re-encode preserves it; otherwise plain ``"utf-8"``. ``newline`` is
    ``"\\r\\n"`` when any CRLF appears in the first 4 KB (Windows-authored
    sources) and ``"\\n"`` otherwise. Sampling rather than scanning the
    whole file keeps detection bounded for large Java files.
    """
    encoding = "utf-8-sig" if raw_bytes.startswith(b"\xef\xbb\xbf") else "utf-8"
    newline = "\r\n" if b"\r\n" in raw_bytes[:4096] else "\n"
    return encoding, newline


def read_source_preserving_format(path: Path) -> tuple[str, str, str]:
    """Read ``path`` and return ``(text, encoding, newline)``.

    Text is returned with line endings normalised to ``"\\n"`` so callers
    can transform it uniformly; the original encoding and newline are
    returned alongside so :func:`write_source_preserving_format` can
    round-trip the write.
    """
    raw = path.read_bytes()
    encoding, newline = detect_text_format(raw)
    text = raw.decode(encoding)
    if newline == "\r\n":
        text = text.replace("\r\n", "\n")
    return text, encoding, newline


def write_source_preserving_format(path: Path, text: str, encoding: str, newline: str) -> None:
    """Write ``text`` to ``path`` re-applying the detected format.

    ``write_text(..., encoding="utf-8")`` would silently strip a UTF-8
    BOM and rewrite CRLF to LF; this helper preserves both.
    """
    payload = text.replace("\n", "\r\n") if newline == "\r\n" else text
    path.write_bytes(payload.encode(encoding))


def format_java_parse_error(exc: Exception) -> str:
    detail = str(exc).strip()
    if detail:
        return f"{exc.__class__.__name__}: {detail}"
    return exc.__class__.__name__


def extract_target_method_identity(target_method: str | None) -> tuple[str | None, int | None]:
    raw = (target_method or "").strip()
    if not raw:
        return None, None
    method_match = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*\((.*)\)", raw)
    if not method_match:
        return None, None
    method_name = method_match.group(1)
    params_block = method_match.group(2).strip()
    if not params_block:
        return method_name, 0
    return method_name, len(_split_signature_parameters(params_block))


def _split_signature_parameters(params_block: str) -> list[str]:
    params: list[str] = []
    current: list[str] = []
    generic_depth = 0
    for char in params_block:
        if char == "<":
            generic_depth += 1
        elif char == ">":
            generic_depth -= 1
        if char == "," and generic_depth == 0:
            value = "".join(current).strip()
            if value:
                params.append(value)
            current = []
            continue
        current.append(char)
    value = "".join(current).strip()
    if value:
        params.append(value)
    return params


def resolve_file_path(file_path: str) -> Path | None:
    path = Path(file_path)
    if path.is_file():
        return path
    workspace_root = Path(settings.upload_dir)
    if not workspace_root.is_absolute():
        workspace_root = _PROJECT_ROOT / workspace_root
    candidate = workspace_root / file_path
    if candidate.is_file():
        return candidate
    candidate = _PROJECT_ROOT / file_path
    if candidate.is_file():
        return candidate
    return None


def _snapshot_for_source(source: str, target_method: str):
    source_bytes = source.encode("utf-8")
    try:
        return create_source_snapshot_from_bytes(
            workspace_root="/workspace",
            source_path="/workspace/RemediationSource.java",
            source_bytes=source_bytes,
            method_selector=target_method,
            expected_source_sha256=sha256_hex(source_bytes),
        )
    except (AmbiguousMethodError, SnapshotError) as exc:
        raise ValueError(str(exc)) from exc


def extract_method_span(source: str, target_method: str) -> tuple[list[str], int, int, str]:
    if not target_method or "(" not in target_method:
        raise ValueError("Unable to parse target method signature")
    snapshot = _snapshot_for_source(source, target_method)
    original_snippet = snapshot.method_source
    return original_snippet.splitlines(), snapshot.start_line, snapshot.end_line, original_snippet


def apply_method_edits(
    original_lines: list[str],
    edits: list[dict[str, Any]],
    target_method: str,
) -> tuple[list[str], str]:
    def lines_match_exact_or_indent_only(actual: list[str], expected: list[str]) -> bool:
        if actual == expected:
            return True
        return [line.lstrip() for line in actual] == [line.lstrip() for line in expected]

    def merge_overlap_lines(left: list[str], right: list[str]) -> list[str] | None:
        max_overlap = min(len(left), len(right))
        for overlap in range(max_overlap, 0, -1):
            if lines_match_exact_or_indent_only(left[-overlap:], right[:overlap]):
                return left + right[overlap:]
        return None

    def resolve_edit_span(declared_start: int, expected_original: list[str]) -> tuple[int, int]:
        expected_length = len(expected_original)
        if declared_start < 1 or declared_start > len(original_lines) or expected_length == 0:
            raise ValueError("edit_span_out_of_bounds")

        direct_end = declared_start + expected_length - 1
        if direct_end <= len(original_lines):
            direct_slice = original_lines[declared_start - 1 : direct_end]
            if lines_match_exact_or_indent_only(direct_slice, expected_original):
                return declared_start, direct_end

        search_start = max(1, declared_start - 1)
        search_end = min(len(original_lines) - expected_length + 1, declared_start + 2)
        matches: list[int] = []
        for candidate_start in range(search_start, search_end + 1):
            candidate_end = candidate_start + expected_length - 1
            if lines_match_exact_or_indent_only(original_lines[candidate_start - 1 : candidate_end], expected_original):
                matches.append(candidate_start)

        if len(matches) == 1:
            candidate_start = matches[0]
            return candidate_start, candidate_start + expected_length - 1
        raise ValueError("edit_original_mismatch")

    effective_edits = [edit for edit in edits if list(edit["original_lines"]) != list(edit["replacement_lines"])]
    if not effective_edits:
        raise ValueError("empty_edits")

    resolved_edits: list[dict[str, Any]] = []
    for edit in effective_edits:
        start_line = edit["start_line"]
        expected_original = edit["original_lines"]
        replacement_lines = edit["replacement_lines"]
        actual_start, actual_end = resolve_edit_span(start_line, expected_original)
        declared_end = edit["end_line"]
        if declared_end < start_line:
            raise ValueError("edit_span_out_of_bounds")
        resolved_edits.append(
            {
                "actual_start": actual_start,
                "actual_end": actual_end,
                "original_lines": expected_original,
                "replacement_lines": replacement_lines,
            }
        )

    resolved_edits.sort(key=lambda item: (item["actual_start"], item["actual_end"]))

    normalized_edits: list[dict[str, Any]] = []
    for edit in resolved_edits:
        if not normalized_edits:
            normalized_edits.append(edit)
            continue
        previous = normalized_edits[-1]
        if edit["actual_start"] > previous["actual_end"]:
            normalized_edits.append(edit)
            continue

        merged_original = merge_overlap_lines(previous["original_lines"], edit["original_lines"])
        merged_replacement = merge_overlap_lines(previous["replacement_lines"], edit["replacement_lines"])
        if merged_original is None or merged_replacement is None:
            raise ValueError("edit_spans_overlap")

        normalized_edits[-1] = {
            "actual_start": previous["actual_start"],
            "actual_end": max(previous["actual_end"], edit["actual_end"]),
            "original_lines": merged_original,
            "replacement_lines": merged_replacement,
        }

    updated_lines = list(original_lines)
    previous_end = 0
    offset = 0
    for edit in normalized_edits:
        expected_original = edit["original_lines"]
        replacement_lines = edit["replacement_lines"]
        actual_start = edit["actual_start"]
        actual_end = edit["actual_end"]
        if actual_start <= previous_end:
            raise ValueError("edit_spans_overlap")

        adjusted_start = actual_start - 1 + offset
        adjusted_end = actual_end + offset
        updated_lines[adjusted_start:adjusted_end] = replacement_lines
        offset += len(replacement_lines) - len(expected_original)
        previous_end = actual_end

    updated_snippet = "\n".join(updated_lines)
    validate_method_shape(updated_lines, target_method)
    return updated_lines, updated_snippet


def validate_method_shape(method_lines: list[str], target_method: str) -> None:
    """Raise ``ValueError`` unless ``method_lines`` is a single method matching ``target_method``.

    Shared by the edit-application and full-method-replacement paths so a malformed
    candidate (e.g. a body collapsed to one line) fails as a clean REPLACEMENT_ERROR
    instead of producing broken source that surfaces later as an opaque lookup failure.
    """
    try:
        fragment = parse_strict_method_fragment("\n".join(method_lines).encode("utf-8"), require_body=True)
    except JavaFragmentError as exc:
        raise ValueError(f"invalid_java_syntax: {exc}") from exc
    parsed_method = fragment.method
    expected_method_name, expected_parameter_count = extract_target_method_identity(target_method)
    if expected_method_name and parsed_method.name != expected_method_name:
        raise ValueError("method_name_mismatch")
    if expected_parameter_count is not None and len(parsed_method.parameters) != expected_parameter_count:
        raise ValueError("parameter_count_mismatch")
