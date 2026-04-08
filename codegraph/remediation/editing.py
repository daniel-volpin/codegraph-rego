from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import javalang
from javalang.tree import MethodDeclaration

from codegraph.config import settings

_PROJECT_ROOT = Path(__file__).resolve().parents[2]


def format_java_parse_error(exc: Exception) -> str:
    detail = str(exc).strip()
    if detail:
        return f"{exc.__class__.__name__}: {detail}"
    return exc.__class__.__name__


def detect_multiline_literal_issue(lines: list[str]) -> str | None:
    in_block_comment = False
    for line in lines:
        in_string = False
        in_char = False
        escaped = False
        index = 0
        while index < len(line):
            char = line[index]
            nxt = line[index + 1] if index + 1 < len(line) else ""

            if in_block_comment:
                if char == "*" and nxt == "/":
                    in_block_comment = False
                    index += 2
                    continue
                index += 1
                continue

            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
                index += 1
                continue

            if in_char:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == "'":
                    in_char = False
                index += 1
                continue

            if char == "/" and nxt == "/":
                break
            if char == "/" and nxt == "*":
                in_block_comment = True
                index += 2
                continue
            if char == '"':
                in_string = True
                index += 1
                continue
            if char == "'":
                in_char = True
                index += 1
                continue
            index += 1

        if in_string:
            return "invalid_java_syntax: multiline_string_literal"
        if in_char:
            return "invalid_java_syntax: multiline_char_literal"
    return None


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
    return method_name, len([part for part in params_block.split(",") if part.strip()])


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


def parse_signature(signature: str) -> tuple[str, list[str]]:
    if not signature:
        return "", []
    base, _, params = signature.partition("(")
    method_name = base.split(".")[-1].strip()
    params = params.rsplit(")", 1)[0]
    param_types = [p.strip() for p in params.split(",") if p.strip()]
    return method_name, param_types


def normalize_type_name(type_name: str) -> str:
    return type_name.split(".")[-1].replace("[]", "").strip()


def params_match(expected: list[str], actual: list[str]) -> bool:
    if expected and len(expected) != len(actual):
        return False
    if not expected:
        return len(actual) == 0
    return all(normalize_type_name(exp) == normalize_type_name(act) for exp, act in zip(expected, actual))


def extract_method_span(source: str, target_method: str) -> tuple[list[str], int, int, str]:
    try:
        tree = javalang.parse.parse(source)
    except Exception as exc:  # pragma: no cover - parser guard
        raise ValueError(f"Failed to parse source file: {exc}") from exc

    method_name, expected_params = parse_signature(target_method)
    if not method_name:
        raise ValueError("Unable to parse target method signature")
    source_lines = source.splitlines()

    match = None
    for _, node in tree.filter(MethodDeclaration):
        if node.name != method_name:
            continue
        actual_params = [
            getattr(param.type, "name", str(param.type))
            for param in getattr(node, "parameters", [])
            if getattr(param, "type", None) is not None
        ]
        if not params_match(expected_params, actual_params):
            continue
        match = node
        break

    if match is None:
        raise ValueError(f"Method {target_method} not found in source file")

    start_line = match.position.line if match.position else None
    if start_line is None:
        raise ValueError("Method position not available for replacement")
    annotation_lines = [
        ann.position.line
        for ann in getattr(match, "annotations", [])
        if getattr(ann, "position", None) and ann.position
    ]
    if annotation_lines:
        start_line = min([start_line, *annotation_lines])

    end_line = infer_method_end_line(source_lines, start_line)
    if end_line is None:
        raise ValueError("Could not determine method end line for replacement")

    original_lines = source_lines[start_line - 1 : end_line]
    original_snippet = "\n".join(original_lines)
    return original_lines, start_line, end_line, original_snippet


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
    multiline_literal_issue = detect_multiline_literal_issue(updated_lines)
    if multiline_literal_issue:
        raise ValueError(multiline_literal_issue)

    wrapped_method = f"class RemediationCandidate {{\n{updated_snippet}\n}}"
    try:
        parsed_wrapper = javalang.parse.parse(wrapped_method)
        parsed_methods = [node for _, node in parsed_wrapper.filter(MethodDeclaration)]
    except Exception as exc:
        raise ValueError(f"invalid_java_syntax: {format_java_parse_error(exc)}") from exc

    if len(parsed_methods) != 1:
        raise ValueError("invalid_method_shape: expected single method declaration")
    parsed_method = parsed_methods[0]
    if not set(parsed_method.modifiers or set()).intersection({"public", "private", "protected"}):
        raise ValueError("invalid_method_shape: missing access_modifier")

    expected_method_name, expected_parameter_count = extract_target_method_identity(target_method)
    if expected_method_name and parsed_method.name != expected_method_name:
        raise ValueError("method_name_mismatch")
    if expected_parameter_count is not None and len(parsed_method.parameters or []) != expected_parameter_count:
        raise ValueError("parameter_count_mismatch")

    return updated_lines, updated_snippet


def replace_method_in_source(source: str, updated_method_lines: list[str], target_method: str) -> tuple[str, str, str]:
    source_lines = source.splitlines()
    _, start_line, end_line, original_snippet = extract_method_span(source, target_method)
    updated_snippet = "\n".join(updated_method_lines)
    new_lines = source_lines[: start_line - 1] + updated_method_lines + source_lines[end_line:]
    new_source = "\n".join(new_lines)
    return new_source, original_snippet, updated_snippet


def infer_method_end_line(lines: list[str], start_line: int) -> int | None:
    brace_count = 0
    started = False
    for idx in range(start_line - 1, len(lines)):
        line = lines[idx]
        for char in line:
            if char == "{":
                brace_count += 1
                started = True
            elif char == "}":
                brace_count -= 1
        if started and brace_count == 0:
            return idx + 1
    return None
