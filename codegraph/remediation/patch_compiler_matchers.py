from __future__ import annotations

import re
from typing import Any


def _find_literal_occurrences(
    target_value: str,
    source_lines: list[str],
    qualifier: str | None,
) -> list[tuple[int, int, int]]:
    """Return 0-based (line,start,end) literal occurrences."""
    matches: list[tuple[int, int, int]] = []
    qualifier_lower = qualifier.lower() if qualifier else None
    pattern = re.compile(re.escape(target_value), re.IGNORECASE)

    for i, line in enumerate(source_lines):
        line_lower = line.lower()
        if qualifier_lower is not None and qualifier_lower not in line_lower:
            continue
        for match in pattern.finditer(line):
            matches.append((i, match.start(), match.end()))
    return matches


def _find_constructor_occurrences(old_type: str, source_lines: list[str]) -> list[tuple[int, int, int]]:
    """Find deduped constructor-call occurrences for FQN and simple type."""
    old_simple = old_type.rsplit(".", 1)[-1]
    escaped_types = [re.escape(old_type), re.escape(old_simple)]
    escaped_types = list(dict.fromkeys(escaped_types))
    patterns = [re.compile(r"new\s+" + typ + r"\s*\(", re.IGNORECASE) for typ in escaped_types]

    deduped: dict[tuple[int, int, int], tuple[int, int, int]] = {}
    for pattern in patterns:
        for occurrence in _find_regex_occurrences(pattern, source_lines):
            deduped[occurrence] = occurrence
    return list(deduped.values())


def _find_regex_occurrences(
    pattern: re.Pattern[str],
    source_lines: list[str],
) -> list[tuple[int, int, int]]:
    """Return 0-based (line,start,end) occurrences for a compiled regex."""
    occurrences: list[tuple[int, int, int]] = []
    for i, line in enumerate(source_lines):
        for match in pattern.finditer(line):
            occurrences.append((i, match.start(), match.end()))
    return occurrences


def _case_insensitive_literal_replace(
    line: str,
    target: str,
    replacement: str,
) -> str:
    """Replace the first case-insensitive match of *target* in *line*."""
    idx = line.lower().find(target.lower())
    if idx == -1:
        return line
    return line[:idx] + replacement + line[idx + len(target) :]


def _call_pattern_to_regex(call_pattern: str) -> str:
    """Convert a method call pattern like ``Math.random()`` into a regex."""
    paren_idx = call_pattern.rfind("(")
    if paren_idx == -1:
        return re.escape(call_pattern)

    caller = call_pattern[:paren_idx].strip()
    args_and_close = call_pattern[paren_idx:]

    parts = caller.split(".")
    escaped_parts = [re.escape(p) for p in parts]

    first_part = r"(?:[\w.]+\.)?" + escaped_parts[0]
    remaining = [r"\s*\.\s*" + p for p in escaped_parts[1:]]

    caller_regex = first_part + "".join(remaining)

    if args_and_close.strip() == "()":
        args_regex = r"\s*\(\s*\)"
    else:
        inner = args_and_close[1:].rstrip(")")
        args_regex = r"\s*\(\s*" + re.escape(inner) + r"\s*\)"

    return caller_regex + args_regex


def validate_non_overlapping_edits(edits: list[dict[str, Any]], compile_error_cls: type[Exception]) -> None:
    """Reject overlapping or conflicting edit spans."""
    for i, left in enumerate(edits):
        l_start = int(left["start_line"])
        l_end = int(left["end_line"])
        for j in range(i + 1, len(edits)):
            right = edits[j]
            r_start = int(right["start_line"])
            r_end = int(right["end_line"])
            if l_start > r_end or r_start > l_end:
                continue

            same_range = l_start == r_start and l_end == r_end
            same_replacement = left["replacement_lines"] == right["replacement_lines"]
            same_original = left["original_lines"] == right["original_lines"]
            if same_range and same_replacement and same_original:
                raise compile_error_cls(f"overlapping_edits: duplicate edits target lines {l_start}-{l_end}")

            if same_range:
                raise compile_error_cls(
                    f"conflicting_edits: multiple edits target lines {l_start}-{l_end} with different replacements"
                )

            raise compile_error_cls(
                f"overlapping_edits: edit spans overlap across lines {l_start}-{l_end} and {r_start}-{r_end}"
            )
