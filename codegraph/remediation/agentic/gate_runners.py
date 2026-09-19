from __future__ import annotations

import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from codegraph.ingestion.snapshots import create_source_snapshot_from_bytes, sha256_hex
from codegraph.java.service import parse_java_source
from codegraph.remediation.scoped_verification import verify_candidate
from codegraph.telemetry import get_tracer

LOGGER = logging.getLogger(__name__)
_tracer = get_tracer("codegraph.remediation.agentic.gates")


def find_build_root(scratch_root: Path) -> Path:
    """Find the Maven pom.xml root in the workspace or subdirectories."""
    if (scratch_root / "pom.xml").exists():
        return scratch_root
    poms = sorted(scratch_root.rglob("pom.xml"), key=lambda p: len(p.parts))
    if poms:
        return poms[0].parent
    return scratch_root


def compile_scratch_workspace(scratch_root: Path, timeout: int = 60) -> tuple[bool, str]:
    """Compile Java sources in the scratch workspace using JDT parser and Maven."""
    with _tracer.start_as_current_span("verification.gate.compilation") as span:
        java_files = [p for p in scratch_root.rglob("*.java") if p.is_file()]
        span.set_attribute("verification.file_count", len(java_files))
        if not java_files:
            span.set_attribute("verification.compile_passed", False)
            return False, "Compilation gate unavailable: no Java source files found."
        for p in java_files:
            try:
                rel = p.relative_to(scratch_root).as_posix()
                res = parse_java_source(
                    p.read_bytes(),
                    relative_path=rel,
                    resolve_bindings=False,
                )
                errors = [d.message for d in res.diagnostics if d.severity == "error"]
                if res.coverage != "complete" or errors:
                    detail = "; ".join(errors) or f"parser coverage was {res.coverage!r}"
                    span.set_attribute("verification.compile_passed", False)
                    span.set_attribute("verification.error_count", len(errors))
                    return False, f"JDT verification failed in {p.name}: {detail}"
            except Exception as exc:
                span.set_attribute("verification.compile_passed", False)
                return False, f"JDT Parser Error in {p.name}: {exc}"

        build_root = find_build_root(scratch_root)
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
                passed = res.returncode == 0
                span.set_attribute("verification.compile_passed", passed)
                if passed:
                    return True, "Maven build succeeded (0 errors)."
                output = (res.stdout + "\n" + res.stderr).strip()
                return False, output or f"Maven compile failed with exit code {res.returncode}."
            except Exception as exc:
                span.set_attribute("verification.compile_passed", False)
                return False, f"Maven compile unavailable: {exc}"

        span.set_attribute("verification.compile_passed", False)
        return False, "Compilation gate unavailable: no supported Maven build was found."


def run_scratch_tests(scratch_root: Path, timeout: int = 60) -> tuple[bool, str]:
    """Run project tests in the scratch workspace to ensure no behavioral regression."""
    with _tracer.start_as_current_span("verification.gate.regression_tests") as span:
        build_root = find_build_root(scratch_root)
        pom = build_root / "pom.xml"
        if not pom.exists():
            span.set_attribute("verification.tests_passed", False)
            return False, "Regression gate unavailable: no supported Maven build was found."
        test_sources = []
        for path in build_root.rglob("*.java"):
            relative_parts = path.relative_to(build_root).parts
            if any(
                relative_parts[index : index + 3] == ("src", "test", "java") for index in range(len(relative_parts) - 2)
            ):
                test_sources.append(path)
        if not test_sources:
            span.set_attribute("verification.tests_passed", True)
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
            passed = res.returncode == 0 and "No tests to run" not in out
            span.set_attribute("verification.tests_passed", passed)
            if passed:
                return True, "Tests passed (0 regressions)."
            return False, out or f"Maven tests failed with exit code {res.returncode}."
        except Exception as exc:
            span.set_attribute("verification.tests_passed", False)
            return False, f"Test execution unavailable: {exc}"


def evaluate_scratch_policy(
    scratch_root: Path,
    temp_dir: Path,
    target_method_key: str | None,
    target_relative_path: Path | None,
    target_original_bytes: bytes | None,
    target_rule_id: str | None = None,
    verify_candidate_fn: Any = None,
) -> tuple[bool, list[dict[str, Any]], list[str]]:
    """Evaluate the target method candidate with the isolated OPA verifier."""
    with _tracer.start_as_current_span("verification.gate.policy_clearance") as span:
        span.set_attribute("verification.target_rule_id", target_rule_id or "")
        if verify_candidate_fn is None:
            verify_candidate_fn = verify_candidate
        if not target_rule_id or not target_method_key or target_relative_path is None:
            span.set_attribute("verification.policy_passed", False)
            return False, [{"error": "policy_target_unavailable"}], [target_rule_id] if target_rule_id else []
        if target_original_bytes is None:
            span.set_attribute("verification.policy_passed", False)
            return False, [{"error": "policy_baseline_source_unavailable"}], [target_rule_id]

        candidate_path = scratch_root / target_relative_path
        if not candidate_path.is_file():
            span.set_attribute("verification.policy_passed", False)
            return False, [{"error": "policy_candidate_source_unavailable"}], [target_rule_id]
        try:
            candidate_bytes = candidate_path.read_bytes()
            baseline_snapshot = create_source_snapshot_from_bytes(
                workspace_root=scratch_root,
                source_path=candidate_path,
                source_bytes=target_original_bytes,
                method_selector=target_method_key,
                expected_source_sha256=sha256_hex(target_original_bytes),
            )
            candidate_snapshot = create_source_snapshot_from_bytes(
                workspace_root=scratch_root,
                source_path=candidate_path,
                source_bytes=candidate_bytes,
                method_selector=baseline_snapshot.identity.selector,
                expected_source_sha256=sha256_hex(candidate_bytes),
            )
            baseline_shell_bytes = (
                candidate_bytes[: candidate_snapshot.start_byte]
                + target_original_bytes[baseline_snapshot.start_byte : baseline_snapshot.end_byte]
                + candidate_bytes[candidate_snapshot.end_byte :]
            )
            with tempfile.TemporaryDirectory(prefix="policy-verification-", dir=temp_dir) as temp:
                verification_root = Path(temp)
                baseline_path = verification_root / target_relative_path
                baseline_path.parent.mkdir(parents=True, exist_ok=True)
                baseline_path.write_bytes(baseline_shell_bytes)
                candidate_method = verification_root / ".candidate" / "candidate-method.java"
                candidate_method.parent.mkdir(parents=True, exist_ok=True)
                candidate_method.write_bytes(candidate_snapshot.method_bytes)
                report = verify_candidate_fn(
                    workspace_root=verification_root,
                    source=target_relative_path,
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
            span.set_attribute("verification.policy_passed", passed)
            span.set_attribute("verification.remaining_violations_count", len(violation_ids))
            if not passed and target_rule_id not in violation_ids:
                violation_ids.append(target_rule_id)
            if not passed and not candidate_findings:
                candidate_findings = [{"error": report.get("error") or report.get("status") or "policy_failed"}]
            return passed, candidate_findings, violation_ids
        except Exception as exc:
            span.set_attribute("verification.policy_passed", False)
            span.set_attribute("verification.error", str(exc))
            LOGGER.warning("Candidate-local policy evaluation failed: %s", exc)
            return False, [{"error": str(exc)}], [target_rule_id]
