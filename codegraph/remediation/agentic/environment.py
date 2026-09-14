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

from codegraph.db import shared_neo4j_driver
from codegraph.ingestion.snapshots import create_source_snapshot_from_bytes, sha256_hex
from codegraph.java.service import parse_java_source
from codegraph.remediation.agentic.contracts import AgentVerificationStatus
from codegraph.remediation.method_key_paths import parse_method_key_relative_path
from codegraph.remediation.scoped_verification import verify_candidate

LOGGER = logging.getLogger(__name__)


class IsolatedWorktreeEnvironment:
    """Manages an isolated scratch workspace for autonomous agent edits and verification."""

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
            target = self.scratch_root / self.target_relative_path
            if target.is_file():
                self._target_original_bytes = target.read_bytes()

    @staticmethod
    def _method_key_relative_path(method_key: str | None) -> Path | None:
        return parse_method_key_relative_path(method_key)

    def _setup_scratch_copy(self) -> None:
        if self.original_root.is_dir():
            shutil.copytree(
                self.original_root,
                self.scratch_root,
                ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache", "target", "node_modules", ".venv"),
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

        # Search matching suffix or filename in scratch workspace
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

    def _find_build_root(self) -> Path:
        """Find the Maven pom.xml root in the workspace or subdirectories."""
        if (self.scratch_root / "pom.xml").exists():
            return self.scratch_root
        poms = sorted(self.scratch_root.rglob("pom.xml"), key=lambda p: len(p.parts))
        if poms:
            return poms[0].parent
        return self.scratch_root

    def compile_workspace(self, timeout: int = 60) -> tuple[bool, str]:
        """Compile Java sources in the scratch workspace using JDT parser and Maven."""
        # 1. Authoritative JDT AST and Syntax Verification on modified Java files
        java_files = [p for p in self.scratch_root.rglob("*.java") if p.is_file()]
        if not java_files:
            return False, "Compilation gate unavailable: no Java source files found."
        for p in java_files:
            try:
                rel = p.relative_to(self.scratch_root).as_posix()
                res = parse_java_source(
                    p.read_bytes(),
                    relative_path=rel,
                    resolve_bindings=False,
                )
                errors = [d.message for d in res.diagnostics if d.severity == "error"]
                if res.coverage != "complete" or errors:
                    detail = "; ".join(errors) or f"parser coverage was {res.coverage!r}"
                    return False, f"JDT verification failed in {p.name}: {detail}"
            except Exception as exc:
                return False, f"JDT Parser Error in {p.name}: {exc}"

        # 2. If Maven build configuration exists, attempt build
        build_root = self._find_build_root()
        pom = build_root / "pom.xml"
        if pom.exists():
            try:
                res = subprocess.run(
                    [
                        "mvn",
                        "--batch-mode",
                        "-q",
                        "-DskipTests",
                        "-Dspotless.apply.skip=true",
                        "-Dspotless.check.skip=true",
                        "compile",
                    ],
                    cwd=build_root,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )
                if res.returncode == 0:
                    return True, "Maven build succeeded (0 errors)."
                output = (res.stdout + "\n" + res.stderr).strip()
                return False, output or f"Maven compile failed with exit code {res.returncode}."
            except Exception as exc:
                return False, f"Maven compile unavailable: {exc}"

        return False, "Compilation gate unavailable: no supported Maven build was found."

    def run_tests(self, timeout: int = 60) -> tuple[bool, str]:
        """Run project tests in the scratch workspace to ensure no behavioral regression."""
        build_root = self._find_build_root()
        pom = build_root / "pom.xml"
        if not pom.exists():
            return False, "Regression gate unavailable: no supported Maven build was found."
        test_sources = []
        for path in build_root.rglob("*.java"):
            relative_parts = path.relative_to(build_root).parts
            if any(
                relative_parts[index : index + 3] == ("src", "test", "java")
                for index in range(len(relative_parts) - 2)
            ):
                test_sources.append(path)
        if not test_sources:
            return True, "Regression gate not applicable: no Java test suite was found (vacuous pass)."
        try:
            res = subprocess.run(
                ["mvn", "--batch-mode", "-q", "-Dspotless.apply.skip=true", "-Dspotless.check.skip=true", "test"],
                cwd=build_root,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            out = (res.stdout + "\n" + res.stderr).strip()
            if res.returncode == 0 and "No tests to run" not in out:
                return True, "Tests passed (0 regressions)."
            return False, out or f"Maven tests failed with exit code {res.returncode}."
        except Exception as exc:
            return False, f"Test execution unavailable: {exc}"

    IGNORED_DIRS = {"classes", "target", "build", "bin", ".git", "__pycache__", ".venv", "node_modules"}
    IGNORED_EXTENSIONS = {".class", ".jar", ".zip", ".tar", ".gz", ".pyc", ".png", ".jpg", ".index"}

    def evaluate_policy(self, target_rule_id: str | None = None) -> tuple[bool, list[dict[str, Any]], list[str]]:
        """Evaluate the target method candidate with the isolated OPA verifier."""
        if not target_rule_id or not self.target_method_key or self.target_relative_path is None:
            return False, [{"error": "policy_target_unavailable"}], [target_rule_id] if target_rule_id else []
        if self._target_original_bytes is None:
            return False, [{"error": "policy_baseline_source_unavailable"}], [target_rule_id]

        candidate_path = self.scratch_root / self.target_relative_path
        if not candidate_path.is_file():
            return False, [{"error": "policy_candidate_source_unavailable"}], [target_rule_id]
        try:
            candidate_bytes = candidate_path.read_bytes()
            baseline_snapshot = create_source_snapshot_from_bytes(
                workspace_root=self.scratch_root,
                source_path=candidate_path,
                source_bytes=self._target_original_bytes,
                method_selector=self.target_method_key,
                expected_source_sha256=sha256_hex(self._target_original_bytes),
            )
            candidate_snapshot = create_source_snapshot_from_bytes(
                workspace_root=self.scratch_root,
                source_path=candidate_path,
                source_bytes=candidate_bytes,
                method_selector=baseline_snapshot.identity.selector,
                expected_source_sha256=sha256_hex(candidate_bytes),
            )
            # Re-verification splices the candidate method onto a "baseline" shell
            # (build_candidate_overlay keeps everything outside the method range from
            # that shell). Using the pristine original file as the shell would drop any
            # import the agent added via add_import(), since that edit sits outside the
            # method's byte range -- the spliced-in method would then reference a type
            # JDT cannot resolve and binding fails with a spurious "not applicable"
            # error. Using the current file's shell (with the original method body
            # swapped back in) keeps the real imports for both the baseline and
            # candidate checks, so only the method body itself differs between them.
            baseline_shell_bytes = (
                candidate_bytes[: candidate_snapshot.start_byte]
                + self._target_original_bytes[baseline_snapshot.start_byte : baseline_snapshot.end_byte]
                + candidate_bytes[candidate_snapshot.end_byte :]
            )
            with tempfile.TemporaryDirectory(prefix="policy-verification-", dir=self.temp_dir) as temp:
                verification_root = Path(temp)
                baseline_path = verification_root / self.target_relative_path
                baseline_path.parent.mkdir(parents=True, exist_ok=True)
                baseline_path.write_bytes(baseline_shell_bytes)
                candidate_method = verification_root / ".candidate" / "candidate-method.java"
                candidate_method.parent.mkdir(parents=True, exist_ok=True)
                candidate_method.write_bytes(candidate_snapshot.method_bytes)
                report = verify_candidate(
                    workspace_root=verification_root,
                    source=self.target_relative_path,
                    # A range-independent selector, not target_method_key: the shell's
                    # byte offsets no longer match the pristine original's, since the
                    # current file's import section can differ in length.
                    method_selector=baseline_snapshot.identity.selector,
                    candidate=candidate_method.relative_to(verification_root),
                    rule_id=target_rule_id,
                    expected_source_sha256=sha256_hex(baseline_shell_bytes),
                    work_dir=verification_root / "work",
                )
            findings_raw = report.get("findings")
            findings: dict[str, Any] = findings_raw if isinstance(findings_raw, dict) else {}
            candidate_findings_raw = findings.get("candidate")
            candidate_findings: list[dict[str, Any]] = (
                [dict(finding) for finding in candidate_findings_raw if isinstance(finding, dict)]
                if isinstance(candidate_findings_raw, list)
                else []
            )
            violation_ids = [
                str(finding.get("violation_id"))
                for finding in candidate_findings
                if isinstance(finding, dict) and finding.get("violation_id")
            ]
            passed = bool(report.get("status") == "POLICY_PASS" and report.get("policy_status") == "PASS")
            if not passed and target_rule_id not in violation_ids:
                violation_ids.append(target_rule_id)
            if not passed and not candidate_findings:
                candidate_findings = [{"error": report.get("error") or report.get("status") or "policy_failed"}]
            return passed, candidate_findings, violation_ids
        except Exception as exc:
            LOGGER.warning("Candidate-local policy evaluation failed: %s", exc)
            return False, [{"error": str(exc)}], [target_rule_id]

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
