"""Graph-aware multi-hop taint path detection.

Uses the in-memory method index (built from Neo4j snapshots) to trace CALLS
edges through user-code methods and identify transitive source→sink paths.
No additional Neo4j queries are needed at evaluation time.

Usage::

    finder = TaintPathFinder(method_index)
    paths  = finder.find_reachable_sinks("workspace@revision:Foo.java#method:bar")
    # [{"sink_type": "sql", "hops": 2}, {"sink_type": "path", "hops": 3}]
"""

from __future__ import annotations

import os
import re
from collections import deque
from pathlib import Path
from typing import Any

from codegraph.policy.source_analysis_core import (
    CMDI_PATTERNS,
    LDAP_PATTERNS,
    PATH_TRAVERSAL_PATTERNS,
    SQL_EXECUTE_CALL_PATTERNS,
    XPATH_PATTERNS,
)

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_THIS_DIR, os.pardir, os.pardir))

# Sink type → tuple of compiled patterns matched against callee source code.
# These reuse the same patterns as the single-method analysis so detection
# semantics stay consistent.
_SINK_SOURCE_PATTERNS: dict[str, tuple[re.Pattern[str], ...]] = {
    "sql": SQL_EXECUTE_CALL_PATTERNS,
    "command": CMDI_PATTERNS,
    "path": PATH_TRAVERSAL_PATTERNS,
    "ldap": (LDAP_PATTERNS[2],),  # .search(
    "xpath": (XPATH_PATTERNS[1],),  # .evaluate(
}


def _resolve_path(file_path: str | None) -> Path | None:
    """Resolve a file path to an existing file, trying absolute then project-relative."""
    if not file_path:
        return None
    p = Path(file_path)
    if p.is_file():
        return p
    candidate = Path(_PROJECT_ROOT) / p
    if candidate.is_file():
        return candidate
    return None


def _ast_sinks_from_evidence(call_evidence: list[dict[str, Any]]) -> set[str]:
    """Extract sink categories directly from AST-resolved invocation evidence."""
    sinks: set[str] = set()
    for call in call_evidence:
        if not isinstance(call, dict):
            continue
        name = str(call.get("name") or "").lower()
        qual = str(call.get("qualifier") or "").lower()
        if name in {"executequery", "executeupdate", "execute", "executebatch"} or "java.sql" in qual or "statement" in qual:
            sinks.add("sql")
        if name in {"exec", "command", "start"} and ("runtime" in qual or "processbuilder" in qual or "process" in qual):
            sinks.add("command")
        if "file" in qual or "paths" in qual or "fileinputstream" in qual or "filereader" in qual:
            sinks.add("path")
        if "search" in name and ("dircontext" in qual or "ldap" in qual):
            sinks.add("ldap")
        if name in {"evaluate", "compile"} and "xpath" in qual:
            sinks.add("xpath")
    return sinks


class TaintPathFinder:
    """Pre-computes which sink types are reachable from any method via BFS.

    The finder operates entirely in Python using the in-memory ``method_index``
    built from Neo4j snapshots. Source code for callees is loaded lazily from
    disk and cached so each file is read at most once per evaluation run.

    Only user-code methods (present in ``method_index``) are traversed. The
    presence of an external sink API (e.g. ``java.sql.Statement.executeQuery``)
    is inferred by checking callee AST invocation evidence first, and falling back
    to source code patterns when AST evidence is incomplete.
    """

    def __init__(self, method_index: dict[str, dict[str, Any]]) -> None:
        self._index = method_index
        self._source_cache: dict[str, str] = {}

    def find_reachable_sinks(
        self,
        method_key: str,
        max_depth: int = 4,
    ) -> list[dict[str, Any]]:
        """BFS the call graph from *method_key*, returning reachable sink types.

        Sink detection starts at depth 1 (direct callees of the evaluated
        method) so as not to duplicate the single-method ``analysis_flags``
        detection performed by the standard policy pipeline.

        Args:
            method_key: Canonical Method.method_key to start from.
            max_depth: Maximum number of CALLS hops to follow (default 4).

        Returns:
            A list of ``{"sink_type": str, "hops": int}`` dicts, one per
            reachable sink type, using the minimum hop count.
        """
        found: dict[str, int] = {}  # sink_type → minimum hop count
        visited: set[str] = {method_key}
        queue: deque[tuple[str, int]] = deque([(method_key, 0)])

        while queue:
            current, depth = queue.popleft()

            # Detect sinks starting at depth 1 (callees, not the root method).
            if depth >= 1:
                snapshot = self._index.get(current)
                if snapshot:
                    ast_sinks = _ast_sinks_from_evidence(snapshot.get("call_evidence") or [])
                    for st in ast_sinks:
                        if st not in found:
                            found[st] = depth
                if len(found) < len(_SINK_SOURCE_PATTERNS):
                    source = self._load_source(current)
                    if source:
                        for sink_type, patterns in _SINK_SOURCE_PATTERNS.items():
                            if sink_type not in found and any(p.search(source) for p in patterns):
                                found[sink_type] = depth
                if len(found) == len(_SINK_SOURCE_PATTERNS):
                    # All sink types found – no need to go deeper.
                    break

            if depth >= max_depth:
                continue

            snapshot = self._index.get(current)
            if snapshot is None:
                continue

            for callee_key in snapshot.get("calls") or ():
                if callee_key and callee_key in self._index and callee_key not in visited:
                    visited.add(callee_key)
                    queue.append((callee_key, depth + 1))

        return [{"sink_type": st, "hops": h} for st, h in found.items()]

    def _load_source(self, method_key: str) -> str:
        """Return source code for *method_key*, loading from disk if needed."""
        if method_key in self._source_cache:
            return self._source_cache[method_key]

        snapshot = self._index.get(method_key)
        if snapshot is None:
            self._source_cache[method_key] = ""
            return ""

        resolved = _resolve_path(snapshot.get("file_path"))
        if resolved is None:
            self._source_cache[method_key] = ""
            return ""

        start_byte = snapshot.get("start_byte")
        end_byte = snapshot.get("end_byte")
        if not isinstance(start_byte, int) or not isinstance(end_byte, int) or end_byte < start_byte:
            self._source_cache[method_key] = ""
            return ""
        raw = resolved.read_bytes()
        source = raw[start_byte:end_byte].decode("utf-8") if end_byte <= len(raw) else ""
        self._source_cache[method_key] = source
        return source
