"""Graph-aware multi-hop taint path detection.

Uses the in-memory method index (built from Neo4j snapshots) to trace CALLS
edges through user-code methods and identify transitive source→sink paths.
No additional Neo4j queries are needed at evaluation time.

Usage::

    finder = TaintPathFinder(method_index)
    paths  = finder.find_reachable_sinks("com.example.Foo.bar()")
    # [{"sink_type": "sql", "hops": 2}, {"sink_type": "path", "hops": 3}]
"""

from __future__ import annotations

import os
import re
from collections import deque
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from codegraph.common.snippet_utils import extract_snippet_by_lines
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
_SINK_SOURCE_PATTERNS: Dict[str, tuple[re.Pattern[str], ...]] = {
    "sql": SQL_EXECUTE_CALL_PATTERNS,
    "command": CMDI_PATTERNS,
    "path": PATH_TRAVERSAL_PATTERNS,
    "ldap": (LDAP_PATTERNS[2],),  # .search(
    "xpath": (XPATH_PATTERNS[1],),  # .evaluate(
}


def _resolve_path(file_path: Optional[str]) -> Optional[Path]:
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


class TaintPathFinder:
    """Pre-computes which sink types are reachable from any method via BFS.

    The finder operates entirely in Python using the in-memory ``method_index``
    built from Neo4j snapshots.  Source code for callees is loaded lazily from
    disk and cached so each file is read at most once per evaluation run.

    Only user-code methods (present in ``method_index``) are traversed.  The
    presence of an external sink API (e.g. ``java.sql.Statement.executeQuery``)
    is inferred by checking callee source code for known sink patterns, since
    external library methods do not have Method nodes in the graph.
    """

    def __init__(self, method_index: Dict[str, Dict[str, Any]]) -> None:
        self._index = method_index
        self._source_cache: Dict[str, str] = {}

    def find_reachable_sinks(
        self,
        signature: str,
        max_depth: int = 4,
    ) -> List[Dict[str, Any]]:
        """BFS the call graph from *signature*, returning reachable sink types.

        Sink detection starts at depth 1 (direct callees of the evaluated
        method) so as not to duplicate the single-method ``analysis_flags``
        detection performed by the standard policy pipeline.

        Args:
            signature: Full or short method signature to start from.
            max_depth: Maximum number of CALLS hops to follow (default 4).

        Returns:
            A list of ``{"sink_type": str, "hops": int}`` dicts, one per
            reachable sink type, using the minimum hop count.
        """
        found: Dict[str, int] = {}  # sink_type → minimum hop count
        visited: Set[str] = {signature}
        queue: deque[tuple[str, int]] = deque([(signature, 0)])

        while queue:
            current, depth = queue.popleft()

            # Detect sinks starting at depth 1 (callees, not the root method).
            if depth >= 1:
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

            for callee_sig in snapshot.get("calls") or ():
                if callee_sig and callee_sig in self._index and callee_sig not in visited:
                    visited.add(callee_sig)
                    queue.append((callee_sig, depth + 1))

        return [{"sink_type": st, "hops": h} for st, h in found.items()]

    def _load_source(self, signature: str) -> str:
        """Return source code for *signature*, loading from disk if needed."""
        if signature in self._source_cache:
            return self._source_cache[signature]

        snapshot = self._index.get(signature)
        if snapshot is None:
            self._source_cache[signature] = ""
            return ""

        resolved = _resolve_path(snapshot.get("file_path"))
        if resolved is None:
            self._source_cache[signature] = ""
            return ""

        source = (
            extract_snippet_by_lines(
                resolved.as_posix(),
                snapshot.get("start_line"),
                snapshot.get("end_line"),
                padding=0,
            )
            or ""
        )
        self._source_cache[signature] = source
        return source
