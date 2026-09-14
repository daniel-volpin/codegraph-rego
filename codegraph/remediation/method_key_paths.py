"""Shared parsing of the file-path segment carried inside a method_key.

A method_key embeds its declaring file's relative path between the workspace
marker (":") and the "#file:"/"#" method-signature suffix. Three call sites
each need the same two-step parse — extract that relative path, then locate
the workspace root a resolved absolute path sits under — but each raises a
different exception on failure to match its own module's error contract.
These functions carry only the parsing; callers keep their own exceptions.
"""

from __future__ import annotations

from pathlib import Path


def parse_method_key_relative_path(method_key: str | None) -> Path | None:
    """Return the relative file path encoded in ``method_key``, or None if unparsable."""
    if not method_key:
        return None
    try:
        _, tail = method_key.split(":", 1)
    except ValueError:
        return None
    relative = tail.split("#file:", 1)[0] if "#file:" in tail else tail.split("#", 1)[0]
    if not relative:
        return None
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts:
        return None
    return path


def resolve_workspace_root(resolved_path: Path, relative_path: Path) -> Path | None:
    """Return the workspace root ``resolved_path`` sits under, given its method_key-relative tail."""
    resolved = resolved_path.resolve()
    relative_parts = relative_path.parts
    if len(resolved.parts) >= len(relative_parts) and resolved.parts[-len(relative_parts) :] == relative_parts:
        root_parts = resolved.parts[: -len(relative_parts)]
        return Path(*root_parts) if root_parts else Path("/")
    return None
