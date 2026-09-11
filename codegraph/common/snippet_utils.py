"""
codegraph/common/snippet_utils.py

Utility for extracting code snippets from source files around a method/function name.
"""

from __future__ import annotations

import logging
from pathlib import Path

LOGGER = logging.getLogger(__name__)


def _read_lines(file_path: Path) -> list[str]:
    with file_path.open("r", encoding="utf-8", errors="ignore") as handle:
        return handle.readlines()


def _iter_java_code_chars(lines: list[str], start_line: int = 1, start_column: int = 0):
    """Yield (line_number, column_index, char) for Java code outside lexical noise."""
    if start_line < 1:
        start_line = 1
    if start_column < 0:
        start_column = 0
    in_block_comment = False
    in_string = False
    in_char = False
    escape = False

    for line_no, line in enumerate(lines, start=1):
        idx = 0
        length = len(line)
        while idx < length:
            ch = line[idx]
            nxt = line[idx + 1] if idx + 1 < length else ""

            if in_block_comment:
                if ch == "*" and nxt == "/":
                    in_block_comment = False
                    idx += 2
                    continue
                idx += 1
                continue

            if in_string:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == '"':
                    in_string = False
                idx += 1
                continue

            if in_char:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == "'":
                    in_char = False
                idx += 1
                continue

            if ch == "/" and nxt == "/":
                break
            if ch == "/" and nxt == "*":
                in_block_comment = True
                idx += 2
                continue
            if ch == '"':
                in_string = True
                idx += 1
                continue
            if ch == "'":
                in_char = True
                idx += 1
                continue

            if line_no > start_line or (line_no == start_line and idx >= start_column):
                yield (line_no, idx, ch)
            idx += 1

        if in_string:
            raise ValueError("unescaped_newline_in_string_literal")
        if in_char:
            raise ValueError("unescaped_newline_in_character_literal")

    if in_block_comment:
        raise ValueError("unterminated_block_comment")
    if in_string:
        raise ValueError("unterminated_string_literal")
    if in_char:
        raise ValueError("unterminated_character_literal")


def find_java_block_end_line(
    lines: list[str], start_line: int | None, start_column: int | None = None
) -> int | None:
    """Find the closing line for a Java block that starts at/after start_line."""
    if not start_line or start_line <= 0 or start_line > len(lines):
        return start_line
    column = start_column if isinstance(start_column, int) else 0
    open_braces = 0
    saw_block_open = False
    for line_no, _col, ch in _iter_java_code_chars(lines, start_line=start_line, start_column=column):
        if ch == "{":
            open_braces += 1
            saw_block_open = True
        elif ch == "}":
            if saw_block_open:
                open_braces -= 1
                if open_braces == 0:
                    return line_no
    if saw_block_open:
        raise ValueError(f"unbalanced_block_from_line_{start_line}")
    raise ValueError(f"missing_block_open_from_line_{start_line}")


def find_java_statement_end_line(
    lines: list[str], start_line: int | None, start_column: int | None = None
) -> int | None:
    """Find terminating semicolon line for a field/statement declaration."""
    if not start_line or start_line <= 0 or start_line > len(lines):
        return start_line
    column = start_column if isinstance(start_column, int) else 0
    paren_depth = 0
    bracket_depth = 0
    brace_depth = 0
    for line_no, _col, ch in _iter_java_code_chars(lines, start_line=start_line, start_column=column):
        if ch == "(":
            paren_depth += 1
            continue
        if ch == ")":
            if paren_depth == 0:
                raise ValueError(f"malformed_statement_unbalanced_closer_from_line_{start_line}")
            paren_depth -= 1
            continue
        if ch == "[":
            bracket_depth += 1
            continue
        if ch == "]":
            if bracket_depth == 0:
                raise ValueError(f"malformed_statement_unbalanced_closer_from_line_{start_line}")
            bracket_depth -= 1
            continue
        if ch == "{":
            brace_depth += 1
            continue
        if ch == "}":
            if brace_depth == 0:
                raise ValueError(f"malformed_statement_unbalanced_closer_from_line_{start_line}")
            brace_depth -= 1
            continue
        if ch == ";" and paren_depth == 0 and bracket_depth == 0 and brace_depth == 0:
            return line_no
    raise ValueError(f"unterminated_statement_from_line_{start_line}")


def select_unique_line_or_refuse(
    lines: list[str], needle: str, start_line_hint: int | None = None
) -> int | None:
    """Return a unique 1-based line match; never return first-on-ambiguity."""
    candidates = [idx for idx, line in enumerate(lines, start=1) if needle in line]
    if not candidates:
        return None
    if start_line_hint is not None:
        if 1 <= start_line_hint <= len(lines) and needle in lines[start_line_hint - 1]:
            return start_line_hint
        return None
    return candidates[0] if len(candidates) == 1 else None


def extract_code_snippet(
    file_path: str,
    needle: str,
    before: int = 8,
    after: int = 24,
    start_line_hint: int | None = None,
) -> str:
    """
    Extract lines around a unique occurrence of `needle` in the file.
    Returns the snippet as a string, or empty string if not found or error.
    """
    try:
        path = Path(file_path)
        lines = _read_lines(path)
        line_no = select_unique_line_or_refuse(lines, needle, start_line_hint=start_line_hint)
        if line_no is None:
            if any(needle in line for line in lines):
                LOGGER.warning("Refusing ambiguous snippet lookup for needle=%r in %s", needle, file_path)
            return ""
        idx = line_no - 1
        start = max(0, idx - before)
        end = min(len(lines), idx + after)
        return "".join(lines[start:end])
    except Exception:
        return ""


def extract_snippet_by_lines(
    file_path: str, start_line: int | None, end_line: int | None, padding: int = 2
) -> str:
    """
    Return the snippet defined by `start_line`/`end_line` (1-based, inclusive).
    Adds optional line padding to give the model a bit of surrounding context.
    """
    if start_line is None and end_line is None:
        return ""
    try:
        path = Path(file_path)
        if not path.is_file():
            return ""
        lines = _read_lines(path)
        total = len(lines)
        start_idx = max(0, (start_line - 1) if start_line else 0)
        end_idx = (end_line - 1) if end_line else start_idx
        start_idx = max(0, start_idx - padding)
        end_idx = min(total - 1, end_idx + padding)
        return "".join(lines[start_idx : end_idx + 1])
    except Exception:
        return ""
