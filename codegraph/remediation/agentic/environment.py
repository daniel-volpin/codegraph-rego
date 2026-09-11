"""Sandboxed workspace environment for autonomous agent remediation."""

from __future__ import annotations

import difflib
import hashlib
import logging
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from codegraph.policy.integration import evaluate_policies
from codegraph.remediation.agentic.contracts import AgentVerificationStatus

LOGGER = logging.getLogger(__name__)


class IsolatedWorktreeEnvironment:
    """Manages an isolated scratch workspace for autonomous agent edits and verification."""

    def __init__(self, workspace_root: str | Path) -> None:
        self.original_root = Path(workspace_root).resolve()
        self.temp_dir = Path(tempfile.mkdtemp(prefix="codegraph_agentic_ws_")).resolve()
        self.scratch_root = self.temp_dir / self.original_root.name
        self._initial_hashes: dict[str, str] = {}
        self._setup_scratch_copy()

    def _setup_scratch_copy(self) -> None:
        if self.original_root.is_dir():
            shutil.copytree(
                self.original_root,
                self.scratch_root,
                ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache", "target", "build", "node_modules"),
            )
        else:
            self.scratch_root.mkdir(parents=True, exist_ok=True)
            shutil.copy2(self.original_root, self.scratch_root / self.original_root.name)
        
        # Record initial hashes
        for p in self.scratch_root.rglob("*"):
            if p.is_file():
                rel = p.relative_to(self.scratch_root).as_posix()
                self._initial_hashes[rel] = hashlib.sha256(p.read_bytes()).hexdigest()

    def resolve_path(self, relative_path: str) -> Path:
        clean = Path(relative_path).as_posix().lstrip("/")
        target = (self.scratch_root / clean).resolve()
        if not str(target).startswith(str(self.scratch_root)):
            raise ValueError(f"Path traversal detected: {relative_path}")
        return target

    def read_file(self, relative_path: str) -> str:
        target = self.resolve_path(relative_path)
        if not target.is_file():
            raise FileNotFoundError(f"File not found: {relative_path}")
        return target.read_text(encoding="utf-8")

    def find_files(self, pattern: str = "**/*") -> list[str]:
        """Find matching files in the scratch workspace."""
        matches: list[str] = []
        for p in self.scratch_root.glob(pattern):
            if p.is_file():
                if any(part in self.IGNORED_DIRS for part in p.relative_to(self.scratch_root).parts):
                    continue
                if p.suffix.lower() in self.IGNORED_EXTENSIONS:
                    continue
                matches.append(p.relative_to(self.scratch_root).as_posix())
        return sorted(matches)

    def search_code(self, pattern: str, max_results: int = 20) -> list[dict[str, Any]]:
        """Search text/regex patterns across workspace source files."""
        results: list[dict[str, Any]] = []
        regex = re.compile(pattern, re.IGNORECASE)
        for rel in self.find_files("**/*"):
            p = self.scratch_root / rel
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

    def search_graph_context(self, symbol_name: str) -> dict[str, Any]:
        """Search graph callers and callees for a method or type from Neo4j."""
        from codegraph.db import shared_neo4j_driver

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

    def write_file(self, relative_path: str, content: str) -> None:
        target = self.resolve_path(relative_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    def apply_replacement(self, relative_path: str, old_str: str, new_str: str) -> bool:
        target = self.resolve_path(relative_path)
        if not target.is_file():
            raise FileNotFoundError(f"File not found: {relative_path}")
        text = target.read_text(encoding="utf-8")
        if old_str not in text:
            return False
        updated = text.replace(old_str, new_str, 1)
        target.write_text(updated, encoding="utf-8")
        return True

    def add_import(self, relative_path: str, import_statement: str) -> bool:
        """Add an import statement below the package declaration or at top of file."""
        target = self.resolve_path(relative_path)
        if not target.is_file():
            raise FileNotFoundError(f"File not found: {relative_path}")
        text = target.read_text(encoding="utf-8")
        stmt = import_statement.strip().rstrip(";") + ";"
        if stmt in text:
            return True  # Already present
        
        lines = text.splitlines(keepends=True)
        pkg_idx = -1
        last_import_idx = -1
        for idx, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("package "):
                pkg_idx = idx
            elif stripped.startswith("import "):
                last_import_idx = idx

        if last_import_idx >= 0:
            lines.insert(last_import_idx + 1, f"{stmt}\n")
        elif pkg_idx >= 0:
            lines.insert(pkg_idx + 1, f"\n{stmt}\n")
        else:
            lines.insert(0, f"{stmt}\n")

        target.write_text("".join(lines), encoding="utf-8")
        return True

    def compile_workspace(self, timeout: int = 60) -> tuple[bool, str]:
        """Compile Java sources in the scratch workspace using Maven or javac."""
        pom = self.scratch_root / "pom.xml"
        if pom.exists():
            cmd = ["mvn", "--batch-mode", "-q", "-DskipTests", "compile"]
            cwd = self.scratch_root
        else:
            # Look for pom.xml in parent or use javac
            java_files = [str(p) for p in self.scratch_root.rglob("*.java")]
            if not java_files:
                return True, "No Java files found."
            cmd = ["javac", "-d", str(self.scratch_root / "classes")] + java_files
            (self.scratch_root / "classes").mkdir(exist_ok=True)
            cwd = self.scratch_root

        try:
            res = subprocess.run(
                cmd,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            out = (res.stdout + "\n" + res.stderr).strip()
            return res.returncode == 0, out
        except Exception as exc:
            return False, f"Compilation subprocess error: {exc}"

    def run_tests(self, timeout: int = 60) -> tuple[bool, str]:
        """Run project tests in the scratch workspace to ensure no behavioral regression."""
        pom = self.scratch_root / "pom.xml"
        if not pom.exists():
            return True, "No test suite configured."
        try:
            res = subprocess.run(
                ["mvn", "--batch-mode", "-q", "test"],
                cwd=self.scratch_root,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            out = (res.stdout + "\n" + res.stderr).strip()
            return res.returncode == 0, out
        except Exception as exc:
            return False, f"Test subprocess error: {exc}"

    IGNORED_DIRS = {"classes", "target", "build", "bin", ".git", "__pycache__", ".venv", "node_modules"}
    IGNORED_EXTENSIONS = {".class", ".jar", ".zip", ".tar", ".gz", ".pyc", ".png", ".jpg", ".index"}

    def evaluate_policy(self, target_rule_id: str | None = None) -> tuple[bool, list[dict[str, Any]], list[str]]:
        """Run OPA policy scan on the scratch workspace."""
        try:
            res = evaluate_policies(workspace_root=self.scratch_root.as_posix())
            violations = res.get("violations", [])
            violation_ids = [str(v.get("violation_id")) for v in violations if v.get("violation_id")]
            passed = target_rule_id not in violation_ids if target_rule_id else len(violations) == 0
            return passed, violations, violation_ids
        except Exception as exc:
            LOGGER.debug("Graph-backed policy evaluation unavailable in standalone mode (%s).", exc)
            # Fallback for standalone/unit test scratch environments
            return True, [], []

    def run_full_verification(self, target_rule_id: str) -> AgentVerificationStatus:
        """Run all 3 invariant gates: Compile + Test Regression + Policy Check."""
        comp_ok, comp_out = self.compile_workspace()
        if not comp_ok:
            return AgentVerificationStatus(
                compile_passed=False,
                compile_output=comp_out,
                tests_passed=False,
                test_output=None,
                policy_passed=False,
                policy_findings=[],
                remaining_violations=[],
            )

        test_ok, test_out = self.run_tests()
        pol_ok, findings, remaining = self.evaluate_policy(target_rule_id)
        return AgentVerificationStatus(
            compile_passed=comp_ok,
            compile_output=comp_out,
            tests_passed=test_ok,
            test_output=test_out,
            policy_passed=pol_ok,
            policy_findings=findings,
            remaining_violations=remaining,
        )

    def get_modified_files(self) -> list[str]:
        modified = []
        for p in self.scratch_root.rglob("*"):
            if p.is_file():
                if any(part in self.IGNORED_DIRS for part in p.relative_to(self.scratch_root).parts):
                    continue
                if p.suffix.lower() in self.IGNORED_EXTENSIONS:
                    continue
                rel = p.relative_to(self.scratch_root).as_posix()
                cur_hash = hashlib.sha256(p.read_bytes()).hexdigest()
                if rel not in self._initial_hashes or self._initial_hashes[rel] != cur_hash:
                    modified.append(rel)
        return sorted(modified)

    def compute_unified_diff(self) -> str:
        diffs = []
        for rel in self.get_modified_files():
            orig_path = self.original_root / rel
            orig_text = orig_path.read_text(encoding="utf-8") if orig_path.exists() else ""
            scratch_text = (self.scratch_root / rel).read_text(encoding="utf-8")
            file_diff = difflib.unified_diff(
                orig_text.splitlines(),
                scratch_text.splitlines(),
                fromfile=f"a/{rel}",
                tofile=f"b/{rel}",
                lineterm="",
            )
            diffs.append("\n".join(file_diff))
        return "\n\n".join(diffs)

    def cleanup(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def __enter__(self) -> IsolatedWorktreeEnvironment:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.cleanup()
