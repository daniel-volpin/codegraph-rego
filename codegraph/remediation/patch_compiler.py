"""
Deterministic patch compiler for Repair Intent IR.

Converts the typed ``operations`` on a :class:`RepairIntent` into the
edit-dict format already consumed by the existing remediation pipeline
(``{start_line, end_line, original_lines, replacement_lines}``).
"""

from __future__ import annotations

import logging
import re
from typing import Any

from codegraph.remediation.patch_compiler_matchers import (
    _call_pattern_to_regex,
    _case_insensitive_literal_replace,
    _find_constructor_occurrences,
    _find_literal_occurrences,
    _find_regex_occurrences,
    validate_non_overlapping_edits,
)
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
    """Compile a :class:`RepairIntent` into downstream edit dicts."""
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
                "import_adjustment is unsupported in deterministic compiler v1; refuse instead of silently ignoring"
            )
        else:
            raise CompileError(f"Unsupported operation type: {type(op).__name__}")

    if not edits:
        raise CompileError("intent produced no executable edits")
    validate_non_overlapping_edits(edits, CompileError)
    return edits


def _compile_literal_replacement(
    op: LiteralReplacementOp,
    source_lines: list[str],
) -> list[dict[str, Any]]:
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
    call = op.old_call_pattern
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
