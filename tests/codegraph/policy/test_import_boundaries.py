from __future__ import annotations

import ast
from pathlib import Path


def test_policy_modules_are_acyclic() -> None:
    repo_root = Path(__file__).resolve().parents[3]
    policy_root = repo_root / "codegraph" / "policy"
    module_paths = {
        path.relative_to(repo_root).with_suffix("").as_posix().replace("/", "."): path
        for path in policy_root.rglob("*.py")
    }
    edges: dict[str, set[str]] = {module: set() for module in module_paths}

    for module, path in module_paths.items():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imported = alias.name
                    if imported in module_paths:
                        edges[module].add(imported)
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                imported = node.module
                if imported in module_paths:
                    edges[module].add(imported)

    index = 0
    stack: list[str] = []
    on_stack: set[str] = set()
    indices: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    components: list[list[str]] = []

    def visit(node: str) -> None:
        nonlocal index
        indices[node] = index
        lowlinks[node] = index
        index += 1
        stack.append(node)
        on_stack.add(node)

        for neighbor in edges[node]:
            if neighbor not in indices:
                visit(neighbor)
                lowlinks[node] = min(lowlinks[node], lowlinks[neighbor])
            elif neighbor in on_stack:
                lowlinks[node] = min(lowlinks[node], indices[neighbor])

        if lowlinks[node] == indices[node]:
            component: list[str] = []
            while True:
                member = stack.pop()
                on_stack.remove(member)
                component.append(member)
                if member == node:
                    break
            if len(component) > 1:
                components.append(sorted(component))

    for module in module_paths:
        if module not in indices:
            visit(module)

    assert not components, f"Policy import cycles detected: {components}"
