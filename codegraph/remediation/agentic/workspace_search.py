from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from codegraph.db import shared_neo4j_driver

IGNORED_DIRS = {"classes", "target", "build", "bin", ".git", "__pycache__", ".venv", "node_modules"}
IGNORED_EXTENSIONS = {".class", ".jar", ".zip", ".tar", ".gz", ".pyc", ".png", ".jpg", ".index"}


def find_workspace_files(scratch_root: Path, pattern: str = "**/*") -> list[str]:
    """Find matching files in the scratch workspace."""
    matches: list[str] = []
    for p in scratch_root.glob(pattern):
        if p.is_file():
            if any(part in IGNORED_DIRS for part in p.relative_to(scratch_root).parts):
                continue
            if p.suffix.lower() in IGNORED_EXTENSIONS:
                continue
            matches.append(p.relative_to(scratch_root).as_posix())
    return sorted(matches)


def search_workspace_code(scratch_root: Path, pattern: str, max_results: int = 20) -> list[dict[str, Any]]:
    """Search text/regex patterns across workspace source files."""
    results: list[dict[str, Any]] = []
    regex = re.compile(pattern, re.IGNORECASE)
    for rel in find_workspace_files(scratch_root, "**/*"):
        p = scratch_root / rel
        try:
            text = p.read_text(encoding="utf-8")
            for line_idx, line in enumerate(text.splitlines(), start=1):
                if regex.search(line):
                    results.append({"file": rel, "line": line_idx, "content": line.strip()})
                    if len(results) >= max_results:
                        return results
        except Exception:
            continue
    return results


def search_graph_callers_callees(symbol_name: str) -> dict[str, Any]:
    """Search graph callers and callees for a method or type from Neo4j."""
    try:
        driver = shared_neo4j_driver()
        with driver.session() as session:
            records = session.run(
                """
                MATCH (m:Method)
                WHERE m.name = $name OR m.signature CONTAINS $name OR m.method_key CONTAINS $name
                OPTIONAL MATCH (caller:Method)-[:CALLS]->(m)
                OPTIONAL MATCH (m)-[:CALLS]->(callee:Method)
                OPTIONAL MATCH (m)-[:USES]->(f:Field)
                RETURN m.signature AS signature,
                       m.method_key AS method_key,
                       m.file_path AS file_path,
                       collect(DISTINCT caller.signature) AS callers,
                       collect(DISTINCT callee.signature) AS callees,
                       collect(DISTINCT f.name) AS uses_fields
                LIMIT 5
                """,
                {"name": symbol_name},
            ).data()
            return {"matches": records}
    except Exception as exc:
        return {"error": f"Graph query unavailable: {exc}"}


def inspect_workspace_class_api(scratch_root: Path, class_name: str) -> dict[str, Any]:
    """Inspect public methods, constructors, and fields of a class in the workspace."""
    clean_name = class_name.split(".")[-1]
    matching_files: list[Path] = []
    for rel in find_workspace_files(scratch_root, f"**/{clean_name}.java"):
        p = scratch_root / rel
        if p.is_file():
            matching_files.append(p)

    if not matching_files:
        # Fallback to search for class declaration across java files
        class_pattern = re.compile(rf"\bclass\s+{re.escape(clean_name)}\b")
        for rel in find_workspace_files(scratch_root, "**/*.java"):
            p = scratch_root / rel
            try:
                if class_pattern.search(p.read_text(encoding="utf-8", errors="ignore")):
                    matching_files.append(p)
                    break
            except Exception:
                continue

    if not matching_files:
        return {"error": f"Class '{class_name}' not found in workspace."}

    target_file = matching_files[0]
    rel_path = target_file.relative_to(scratch_root).as_posix()
    content = target_file.read_text(encoding="utf-8", errors="ignore")

    method_sig_pattern = re.compile(
        r"^\s*(public|protected)\s+(?:static\s+)?(?:final\s+)?([\w<>\[\],\s]+?)\s+(\w+)\s*\(([^)]*)\)\s*(?:throws\s+[\w,\s]+)?\s*[{;]",
        re.MULTILINE,
    )
    escaped_name = re.escape(clean_name)
    constructor_pattern = re.compile(
        r"^\s*(public|protected)\s+" + escaped_name + r"\s*\(([^)]*)\)\s*(?:throws\s+[\w,\s]+)?\s*[{;]",
        re.MULTILINE,
    )
    field_pattern = re.compile(
        r"^\s*(public|protected)\s+(?:static\s+)?(?:final\s+)?([\w<>\[\],\s]+?)\s+(\w+)\s*(?:=[^;]+)?;",
        re.MULTILINE,
    )

    methods = []
    for m in method_sig_pattern.finditer(content):
        vis, ret_type, m_name, params = m.groups()
        methods.append(f"{vis} {ret_type.strip()} {m_name}({params.strip()})")

    constructors = []
    for c in constructor_pattern.finditer(content):
        vis, params = c.groups()
        constructors.append(f"{vis} {clean_name}({params.strip()})")

    fields = []
    for f in field_pattern.finditer(content):
        vis, f_type, f_name = f.groups()
        fields.append(f"{vis} {f_type.strip()} {f_name}")

    return {
        "class_name": clean_name,
        "file_path": rel_path,
        "constructors": constructors[:10],
        "methods": methods[:30],
        "fields": fields[:10],
    }

