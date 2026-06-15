from __future__ import annotations

import ast
from pathlib import Path

ImportGraph = dict[str, set[str]]


def policy_module_paths(repo_root: Path) -> dict[str, Path]:
    policy_root = repo_root / "codegraph" / "policy"
    return {
        path.relative_to(repo_root).with_suffix("").as_posix().replace("/", "."): path
        for path in policy_root.rglob("*.py")
    }


def direct_policy_imports(path: Path, known_modules: set[str]) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names if alias.name in known_modules)
        if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module in known_modules:
            imports.add(node.module)
    return imports


def build_import_graph(module_paths: dict[str, Path]) -> ImportGraph:
    known_modules = set(module_paths)
    return {
        module: direct_policy_imports(path, known_modules)
        for module, path in module_paths.items()
    }


class StronglyConnectedComponents:
    def __init__(self, graph: ImportGraph) -> None:
        self.graph = graph
        self.index = 0
        self.stack: list[str] = []
        self.on_stack: set[str] = set()
        self.indices: dict[str, int] = {}
        self.lowlinks: dict[str, int] = {}
        self.components: list[list[str]] = []

    def find_cycles(self) -> list[list[str]]:
        for module in self.graph:
            if module not in self.indices:
                self._visit(module)
        return self.components

    def _visit(self, module: str) -> None:
        self._push(module)
        for neighbor in self.graph[module]:
            self._visit_neighbor(module, neighbor)
        if self.lowlinks[module] == self.indices[module]:
            self._record_component(module)

    def _push(self, module: str) -> None:
        self.indices[module] = self.index
        self.lowlinks[module] = self.index
        self.index += 1
        self.stack.append(module)
        self.on_stack.add(module)

    def _visit_neighbor(self, module: str, neighbor: str) -> None:
        if neighbor not in self.indices:
            self._visit(neighbor)
            self.lowlinks[module] = min(self.lowlinks[module], self.lowlinks[neighbor])
            return
        if neighbor in self.on_stack:
            self.lowlinks[module] = min(self.lowlinks[module], self.indices[neighbor])

    def _record_component(self, root: str) -> None:
        component: list[str] = []
        while self.stack:
            member = self.stack.pop()
            self.on_stack.remove(member)
            component.append(member)
            if member == root:
                break
        if len(component) > 1:
            self.components.append(sorted(component))


def test_policy_modules_are_acyclic() -> None:
    repo_root = Path(__file__).resolve().parents[3]
    graph = build_import_graph(policy_module_paths(repo_root))

    cycles = StronglyConnectedComponents(graph).find_cycles()

    assert not cycles, f"Policy import cycles detected: {cycles}"
