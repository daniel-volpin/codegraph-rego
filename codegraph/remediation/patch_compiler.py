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
    StructuredEditOp,
)

LOGGER = logging.getLogger(__name__)


class CompileError(Exception):
    """Raised when an operation cannot be deterministically compiled."""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


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
        return []

    edits: list[dict[str, Any]] = []
    for op in intent.operations:
        if isinstance(op, LiteralReplacementOp):
            edits.extend(_compile_literal_replacement(op, source_lines))
        elif isinstance(op, ConstructorReplacementOp):
            edits.extend(_compile_constructor_replacement(op, source_lines))
        elif isinstance(op, MethodCallReplacementOp):
            edits.extend(_compile_method_call_replacement(op, source_lines))
        elif isinstance(op, StructuredEditOp):
            edits.extend(_compile_structured_edit(op, source_lines))
        elif isinstance(op, ImportAdjustmentOp):
            # Import adjustments are informational in v1 — they declare
            # intent but do not produce method-local edits.
            LOGGER.debug("Skipping import_adjustment op (v1: informational only)")
        else:
            raise CompileError(f"Unsupported operation type: {type(op).__name__}")

    return edits


# ---------------------------------------------------------------------------
# Per-operation compilers
# ---------------------------------------------------------------------------


def _compile_literal_replacement(
    op: LiteralReplacementOp,
    source_lines: list[str],
) -> list[dict[str, Any]]:
    """Find a literal string value in source and produce an edit replacing it."""
    target = op.target_value
    replacement = op.replacement_value
    qualifier = op.qualifier_call

    matching_indices = _find_literal_lines(target, source_lines, qualifier)
    if not matching_indices:
        raise CompileError(
            f"literal_replacement: target_value {target!r} not found in source"
            + (f" (qualifier={qualifier!r})" if qualifier else "")
        )
    if len(matching_indices) > 1:
        raise CompileError(
            f"literal_replacement: target_value {target!r} found on {len(matching_indices)} lines, ambiguous match"
        )

    line_idx = matching_indices[0]
    original_line = source_lines[line_idx]
    # Case-insensitive replacement of the literal value within the line.
    replaced_line = _case_insensitive_literal_replace(original_line, target, replacement)

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
    old_simple = op.old_type.rsplit(".", 1)[-1]
    old_patterns = [re.escape(op.old_type), re.escape(old_simple)]
    # Deduplicate if old_type has no package qualifier.
    old_patterns = list(dict.fromkeys(old_patterns))

    matching_indices: list[int] = []
    matched_pattern: str | None = None

    for pat_str in old_patterns:
        pattern = re.compile(r"new\s+" + pat_str + r"\s*\(", re.IGNORECASE)
        indices = [i for i, line in enumerate(source_lines) if pattern.search(line)]
        if indices:
            matching_indices = indices
            matched_pattern = pat_str
            break

    if not matching_indices:
        raise CompileError(f"constructor_replacement: 'new {op.old_type}(' not found in source")
    if len(matching_indices) > 1:
        raise CompileError(
            f"constructor_replacement: 'new {op.old_type}(' found on {len(matching_indices)} lines, ambiguous match"
        )

    line_idx = matching_indices[0]
    original_line = source_lines[line_idx]
    assert matched_pattern is not None  # ensured by matching_indices check

    replace_pattern = re.compile(r"new\s+" + matched_pattern + r"\s*\(", re.IGNORECASE)
    replaced_line = replace_pattern.sub(f"new {op.new_type}(", original_line, count=1)

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
    matching_indices = [i for i, line in enumerate(source_lines) if pattern.search(line)]

    if not matching_indices:
        raise CompileError(f"method_call_replacement: pattern {call!r} not found in source")
    if len(matching_indices) > 1:
        raise CompileError(
            f"method_call_replacement: pattern {call!r} found on {len(matching_indices)} lines, ambiguous match"
        )

    line_idx = matching_indices[0]
    original_line = source_lines[line_idx]
    replaced_line = pattern.sub(op.new_call_expression, original_line, count=1)

    return [
        {
            "start_line": line_idx + 1,
            "end_line": line_idx + 1,
            "original_lines": [original_line],
            "replacement_lines": [replaced_line],
        }
    ]


def _compile_structured_edit(
    op: StructuredEditOp,
    source_lines: list[str],
) -> list[dict[str, Any]]:
    if op.start_line < 1 or op.end_line < op.start_line:
        raise CompileError("structured_edit: invalid span")
    if op.end_line > len(source_lines):
        raise CompileError("structured_edit: span exceeds method length")
    actual_original = source_lines[op.start_line - 1 : op.end_line]
    if actual_original != op.original_lines:
        raise CompileError("structured_edit: original lines do not match source")
    return [
        {
            "start_line": op.start_line,
            "end_line": op.end_line,
            "original_lines": list(op.original_lines),
            "replacement_lines": list(op.replacement_lines),
        }
    ]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _find_literal_lines(
    target_value: str,
    source_lines: list[str],
    qualifier: str | None,
) -> list[int]:
    """Return 0-based line indices where *target_value* appears.

    When *qualifier* is set, only lines also containing the qualifier
    call are considered.
    """
    indices: list[int] = []
    target_lower = target_value.lower()
    qualifier_lower = qualifier.lower() if qualifier else None

    for i, line in enumerate(source_lines):
        line_lower = line.lower()
        if target_lower not in line_lower:
            continue
        if qualifier_lower is not None and qualifier_lower not in line_lower:
            continue
        indices.append(i)
    return indices


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
