"""
codegraph/common/snippet_utils.py

Utility for extracting code snippets from source files around a method/function name.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional


def _read_lines(file_path: Path) -> list[str]:
    with file_path.open("r", encoding="utf-8", errors="ignore") as handle:
        return handle.readlines()


def extract_code_snippet(file_path: str, needle: str, before: int = 8, after: int = 24) -> str:
    """
    Extract lines around the first occurrence of `needle` in the file.
    Returns the snippet as a string, or empty string if not found or error.
    """
    try:
        path = Path(file_path)
        lines = _read_lines(path)
        idx_candidates = [i for i, line in enumerate(lines) if needle in line]
        if not idx_candidates:
            return ""
        idx = idx_candidates[0]
        start = max(0, idx - before)
        end = min(len(lines), idx + after)
        return "".join(lines[start:end])
    except Exception:
        return ""


def extract_snippet_by_lines(
    file_path: str, start_line: Optional[int], end_line: Optional[int], padding: int = 2
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
