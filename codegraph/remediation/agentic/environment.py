"""Sandboxed workspace environment for autonomous agent remediation."""

from __future__ import annotations

import difflib
import hashlib
import logging
import shutil
import tempfile
from pathlib import Path
from typing import Any

from codegraph.remediation.agentic.contracts import AgentVerificationStatus
from codegraph.remediation.agentic.gate_runners import (
    compile_scratch_workspace,
    evaluate_scratch_policy,
    find_build_root,
    run_scratch_tests,
)
from codegraph.remediation.agentic.workspace_search import (
    IGNORED_DIRS,
    IGNORED_EXTENSIONS,
    find_workspace_files,
    search_graph_callers_callees,
    search_workspace_code,
)
from codegraph.remediation.method_key_paths import parse_method_key_relative_path
from codegraph.remediation.scoped_verification import verify_candidate

__all__ = ["IsolatedWorktreeEnvironment", "verify_candidate"]

LOGGER = logging.getLogger(__name__)


class IsolatedWorktreeEnvironment:
    """Manages an isolated scratch workspace for autonomous agent edits and verification."""

    IGNORED_DIRS = IGNORED_DIRS
    IGNORED_EXTENSIONS = IGNORED_EXTENSIONS

    def __init__(self, workspace_root: str | Path, *, target_method_key: str | None = None) -> None:
        self.original_root = Path(workspace_root).resolve()
        self.temp_dir = Path(tempfile.mkdtemp(prefix="codegraph_agentic_ws_")).resolve()
        self.scratch_root = self.temp_dir / self.original_root.name
        self._initial_hashes: dict[str, str] = {}
        self.target_method_key = target_method_key
        self.target_relative_path = self._method_key_relative_path(target_method_key)
        self._target_original_bytes: bytes | None = None
        self._setup_scratch_copy()
        if self.target_relative_path is not None:
            try:
                target = self.resolve_path(str(self.target_relative_path))
                if target.is_file():
                    self.target_relative_path = target.relative_to(self.scratch_root)
                    self._target_original_bytes = target.read_bytes()
            except Exception:
                pass

    @staticmethod
    def _method_key_relative_path(method_key: str | None) -> Path | None:
        return parse_method_key_relative_path(method_key)

    def _setup_scratch_copy(self) -> None:
        if self.original_root.is_dir():
            shutil.copytree(
                self.original_root,
                self.scratch_root,
                ignore=shutil.ignore_patterns(
                    ".git", "__pycache__", ".pytest_cache", "target", "node_modules", ".venv"
                ),
            )
        else:
            self.scratch_root.mkdir(parents=True, exist_ok=True)
            shutil.copy2(self.original_root, self.scratch_root / self.original_root.name)

        for p in self.scratch_root.rglob("*"):
            if p.is_file():
                rel = p.relative_to(self.scratch_root).as_posix()
                self._initial_hashes[rel] = hashlib.sha256(p.read_bytes()).hexdigest()

    def resolve_path(self, relative_path: str) -> Path:
        clean = Path(relative_path).as_posix().lstrip("/")
        target = (self.scratch_root / clean).resolve()
        if target.is_file() and str(target).startswith(str(self.scratch_root)):
            return target

        if clean.startswith(self.scratch_root.name + "/"):
            stripped = clean[len(self.scratch_root.name) + 1 :]
            sub_target = (self.scratch_root / stripped).resolve()
            if sub_target.is_file() and str(sub_target).startswith(str(self.scratch_root)):
                return sub_target

        p = Path(clean)
        candidates = list(self.scratch_root.rglob(p.name))
        for cand in candidates:
            if cand.is_file() and str(cand).startswith(str(self.scratch_root)):
                return cand.resolve()

        if not str(target).startswith(str(self.scratch_root)):
            raise ValueError(f"Path traversal detected: {relative_path}")
        return target

    def read_file(self, relative_path: str) -> str:
        target = self.resolve_path(relative_path)
        if not target.is_file():
            raise FileNotFoundError(f"File not found: {relative_path}")
        return target.read_text(encoding="utf-8")

    def find_files(self, pattern: str = "**/*") -> list[str]:
        return find_workspace_files(self.scratch_root, pattern)

    def search_code(self, pattern: str, max_results: int = 20) -> list[dict[str, Any]]:
        return search_workspace_code(self.scratch_root, pattern, max_results=max_results)

    def search_graph_context(self, symbol_name: str) -> dict[str, Any]:
        return search_graph_callers_callees(symbol_name)

    def write_file(self, relative_path: str, content: str) -> None:
        target = self.resolve_path(relative_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")

    def apply_replacement(self, relative_path: str, old_str: str, new_str: str) -> bool:
        target = self.resolve_path(relative_path)
        if not target.is_file():
            raise FileNotFoundError(f"File not found: {relative_path}")
        text = target.read_text(encoding="utf-8")
        if old_str in text:
            updated = text.replace(old_str, new_str, 1)
            target.write_text(updated, encoding="utf-8")
            return True

        has_crlf = "\r\n" in text
        text_lf = text.replace("\r\n", "\n")
        old_lf = old_str.replace("\r\n", "\n")
        new_lf = new_str.replace("\r\n", "\n")
        if old_lf in text_lf:
            updated_lf = text_lf.replace(old_lf, new_lf, 1)
            updated = updated_lf.replace("\n", "\r\n") if has_crlf else updated_lf
            target.write_text(updated, encoding="utf-8")
            return True
        return False

    def add_import(self, relative_path: str, import_statement: str) -> bool:
        target = self.resolve_path(relative_path)
        if not target.is_file():
            raise FileNotFoundError(f"File not found: {relative_path}")
        text = target.read_text(encoding="utf-8")
        raw_stmt = import_statement.strip().rstrip(";")
        if not raw_stmt.startswith("import "):
            raw_stmt = f"import {raw_stmt}"
        stmt = f"{raw_stmt};"
        if stmt in text:
            return True
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

    def _find_build_root(self) -> Path:
        return find_build_root(self.scratch_root)

    def compile_workspace(self, timeout: int = 60) -> tuple[bool, str]:
        return compile_scratch_workspace(self.scratch_root, timeout=timeout)

    def run_tests(self, timeout: int = 60) -> tuple[bool, str]:
        return run_scratch_tests(self.scratch_root, timeout=timeout)

    def evaluate_policy(self, target_rule_id: str | None = None) -> tuple[bool, list[dict[str, Any]], list[str]]:
        return evaluate_scratch_policy(
            scratch_root=self.scratch_root,
            temp_dir=self.temp_dir,
            target_method_key=self.target_method_key,
            target_relative_path=self.target_relative_path,
            target_original_bytes=self._target_original_bytes,
            target_rule_id=target_rule_id,
            verify_candidate_fn=verify_candidate,
        )

    def run_full_verification(self, target_rule_id: str) -> AgentVerificationStatus:
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
