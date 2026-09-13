"""
Deterministic patch compiler for Repair Intent IR.

Converts the typed ``operations`` on a :class:`RepairIntent` into the
edit-dict format already consumed by the existing remediation pipeline
(``{start_line, end_line, original_lines, replacement_lines}``).

This module is **shadow-mode only**.  It is not wired into the live
remediation flow.  All matching is string-level and deterministic —
no Java AST parsing is introduced in v1.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from codegraph.remediation.repair_intent import (
    ConstructorReplacementOp,
    ImportAdjustmentOp,
    LiteralReplacementOp,
    MethodCallReplacementOp,
    RepairIntent,
    RepairIntentKind,
)

LOGGER = logging.getLogger(__name__)


class CompileError(Exception):
    """Raised when an operation cannot be deterministically compiled."""




def compile_repair_intent(
    intent: RepairIntent,
    source_lines: list[str],
) -> list[dict[str, Any]]:
    """Compile a :class:`RepairIntent` into downstream edit dicts.

    Parameters
    ----------
    intent:
        A fully validated repair intent with populated ``operations``.
    source_lines:
        The method-local source lines (1-indexed start_line expected by
        downstream ``apply_method_edits``).  Each element is a single
        line of Java source without trailing newlines.

    Returns
    -------
    list[dict[str, Any]]
        Edit dicts shaped ``{start_line, end_line, original_lines,
        replacement_lines}``, ready for consumption by the existing
        ``editing.apply_method_edits`` function.

    Raises
    ------
    CompileError
        When an operation matches zero or more than one location in the
        source (ambiguous match), or when the operation type is not
        supported by the v1 compiler.
    """
    if intent.kind == RepairIntentKind.NO_REPAIR:
        return []

    if not intent.operations:
        raise CompileError("intent has no executable operations")

    edits: list[dict[str, Any]] = []
    for op in intent.operations:
        if isinstance(op, LiteralReplacementOp):
            edits.extend(_compile_literal_replacement(op, source_lines))
        elif isinstance(op, ConstructorReplacementOp):
            edits.extend(_compile_constructor_replacement(op, source_lines))
        elif isinstance(op, MethodCallReplacementOp):
            edits.extend(_compile_method_call_replacement(op, source_lines))
        elif isinstance(op, ImportAdjustmentOp):
            raise CompileError(
                "import_adjustment is unsupported in deterministic compiler v1; "
                "refuse instead of silently ignoring"
            )
        else:
            raise CompileError(f"Unsupported operation type: {type(op).__name__}")

    if not edits:
        raise CompileError("intent produced no executable edits")
    _validate_non_overlapping_edits(edits)
    return edits




def _compile_literal_replacement(
    op: LiteralReplacementOp,
    source_lines: list[str],
) -> list[dict[str, Any]]:
    """Find a literal string value in source and produce an edit replacing it."""
    target = op.target_value
    replacement = op.replacement_value
    qualifier = op.qualifier_call

    matches = _find_literal_occurrences(target, source_lines, qualifier)
    if not matches:
        raise CompileError(
            f"literal_replacement: target_value {target!r} not found in source"
            + (f" (qualifier={qualifier!r})" if qualifier else "")
        )
    if len(matches) > 1:
        raise CompileError(
            f"literal_replacement: target_value {target!r} matched {len(matches)} occurrences, ambiguous match"
        )

    line_idx, _, _ = matches[0]
    original_line = source_lines[line_idx]
    # Case-insensitive replacement of the literal value within the line.
    replaced_line = _case_insensitive_literal_replace(original_line, target, replacement)
    if replaced_line == original_line:
        raise CompileError("literal_replacement: replacement is non-operative")

    return [
        {
            "start_line": line_idx + 1,
            "end_line": line_idx + 1,
            "original_lines": [original_line],
            "replacement_lines": [replaced_line],
        }
    ]


def _compile_constructor_replacement(
    op: ConstructorReplacementOp,
    source_lines: list[str],
) -> list[dict[str, Any]]:
    """Find a constructor ``new OldType(`` and replace with ``new NewType(``."""
    # Build a regex that matches "new OldType(" with optional whitespace,
    # allowing both fully-qualified and simple class names.
    occurrences = _find_constructor_occurrences(op.old_type, source_lines)
    if not occurrences:
        raise CompileError(f"constructor_replacement: 'new {op.old_type}(' not found in source")
    if len(occurrences) > 1:
        raise CompileError(
            f"constructor_replacement: 'new {op.old_type}(' matched {len(occurrences)} occurrences, ambiguous match"
        )

    line_idx, start, end = occurrences[0]
    original_line = source_lines[line_idx]
    replaced_line = original_line[:start] + f"new {op.new_type}(" + original_line[end:]
    if replaced_line == original_line:
        raise CompileError("constructor_replacement: replacement is non-operative")

    return [
        {
            "start_line": line_idx + 1,
            "end_line": line_idx + 1,
            "original_lines": [original_line],
            "replacement_lines": [replaced_line],
        }
    ]


def _compile_method_call_replacement(
    op: MethodCallReplacementOp,
    source_lines: list[str],
) -> list[dict[str, Any]]:
    """Find a method call pattern and replace with the new expression."""
    call = op.old_call_pattern
    # Build a flexible regex from the call pattern:
    # - Allow optional whitespace around dots and before parens
    # - Allow optional package prefixes
    escaped = _call_pattern_to_regex(call)

    pattern = re.compile(escaped, re.IGNORECASE)
    occurrences = _find_regex_occurrences(pattern, source_lines)

    if not occurrences:
        raise CompileError(f"method_call_replacement: pattern {call!r} not found in source")
    if len(occurrences) > 1:
        raise CompileError(
            f"method_call_replacement: pattern {call!r} matched {len(occurrences)} occurrences, ambiguous match"
        )

    line_idx = occurrences[0][0]
    original_line = source_lines[line_idx]
    replaced_line = pattern.sub(op.new_call_expression, original_line, count=1)
    if replaced_line == original_line:
        raise CompileError("method_call_replacement: replacement is non-operative")

    return [
        {
            "start_line": line_idx + 1,
            "end_line": line_idx + 1,
            "original_lines": [original_line],
            "replacement_lines": [replaced_line],
        }
    ]




def _find_literal_occurrences(
    target_value: str,
    source_lines: list[str],
    qualifier: str | None,
) -> list[tuple[int, int, int]]:
    """Return 0-based (line,start,end) literal occurrences.

    When *qualifier* is set, only lines also containing the qualifier
    call are considered.
    """
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
    """Convert a method call pattern like ``Math.random()`` into a regex.

    Handles:
    - Optional whitespace around ``.``
    - Optional whitespace before ``(``
    - Optional package prefixes before the class name
    - Content inside parentheses (matched non-greedy)
    """
    # Split on the last '(' to separate caller from args.
    paren_idx = call_pattern.rfind("(")
    if paren_idx == -1:
        return re.escape(call_pattern)

    caller = call_pattern[:paren_idx].strip()
    args_and_close = call_pattern[paren_idx:]

    # Split caller on '.' to get parts.
    parts = caller.split(".")
    escaped_parts = [re.escape(p) for p in parts]

    # Allow optional package prefixes before the first part.
    first_part = r"(?:[\w.]+\.)?" + escaped_parts[0]
    remaining = [r"\s*\.\s*" + p for p in escaped_parts[1:]]

    caller_regex = first_part + "".join(remaining)

    # Handle args: if "()" then match empty parens; otherwise match content.
    if args_and_close.strip() == "()":
        args_regex = r"\s*\(\s*\)"
    else:
        # Match the literal content inside parens.
        inner = args_and_close[1:].rstrip(")")
        args_regex = r"\s*\(\s*" + re.escape(inner) + r"\s*\)"

    return caller_regex + args_regex


def _validate_non_overlapping_edits(edits: list[dict[str, Any]]) -> None:
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
                raise CompileError(
                    f"overlapping_edits: duplicate edits target lines {l_start}-{l_end}"
                )

            if same_range:
                raise CompileError(
                    f"conflicting_edits: multiple edits target lines {l_start}-{l_end} with different replacements"
                )

            raise CompileError(
                "overlapping_edits: edit spans overlap across "
                f"lines {l_start}-{l_end} and {r_start}-{r_end}"
            )
