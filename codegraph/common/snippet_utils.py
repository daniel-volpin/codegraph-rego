"""
codegraph/common/snippet_utils.py

Utility for extracting code snippets from source files around a method/function name.
"""
from typing import Optional

def extract_code_snippet(file_path: str, needle: str, before: int = 8, after: int = 24) -> str:
    """
    Extract lines around the first occurrence of `needle` in the file.
    Returns the snippet as a string, or empty string if not found or error.
    """
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        idx_candidates = [i for i, line in enumerate(lines) if needle in line]
        if not idx_candidates:
            return ""
        idx = idx_candidates[0]
        start = max(0, idx - before)
        end = min(len(lines), idx + after)
        return "".join(lines[start:end])
    except Exception:
        return ""
