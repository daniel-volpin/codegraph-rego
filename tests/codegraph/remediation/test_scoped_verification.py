from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from codegraph.ingestion.snapshots import sha256_hex
from codegraph.policy.engines import DetectionEngine
from codegraph.remediation.scoped_verification import verify_candidate

OPA_AVAILABLE = shutil.which("opa") is not None


def _fake_engine(verify_candidate_fn):
    return DetectionEngine(
        name="opengrep",
        discover_rule_ids=lambda: {"ISO-A.8-CMD-INJECTION"},
        evaluate=lambda **_kwargs: [],
        verify_candidate=verify_candidate_fn,
    )


def _write_case(root: Path, source: str, candidate: str) -> tuple[Path, Path]:
    source_path = root / "src" / "Crypto.java"
    source_path.parent.mkdir(parents=True)
    candidate_path = root / "candidate.java"
    source_path.write_text(source, encoding="utf-8")
    candidate_path.write_text(candidate, encoding="utf-8")
    return source_path, candidate_path


BASE_SOURCE = """package demo;
class Crypto {
  public void hash() throws java.security.NoSuchAlgorithmException {
    java.security.MessageDigest.getInstance("MD5");
  }
}
"""


def test_invalid_policy_catalog_returns_structured_error(monkeypatch, tmp_path) -> None:
    from codegraph.remediation import scoped_verification

    source, candidate = _write_case(tmp_path, BASE_SOURCE, "public void hash() {}")
    policy = tmp_path / "policy"
    policy.mkdir()
    (policy / "catalog.json").write_text('{"controls": {}}', encoding="utf-8")
    monkeypatch.setattr(scoped_verification, "create_source_snapshot", lambda **_kwargs: object())
    monkeypatch.setattr(scoped_verification, "_opa_version", lambda: "test-engine")

    result = verify_candidate(
        workspace_root=tmp_path,
        source=source,
        method_selector="demo.Crypto#hash()",
        candidate=candidate,
        rule_id="ISO-A.10-WEAK-HASH",
        expected_source_sha256=sha256_hex(source.read_bytes()),
        policy_dir=policy,
        work_dir=tmp_path / "work",
    )
    assert result["status"] == "OPA_ERROR"
    assert result["error"] == "policy_catalog_invalid"
    assert source.read_text(encoding="utf-8") == BASE_SOURCE


def test_scoped_verification_routes_opengrep_rule_to_its_engine_and_passes(monkeypatch, tmp_path) -> None:
    from codegraph.remediation import scoped_verification

    source, candidate = _write_case(tmp_path, BASE_SOURCE, "public void hash() {}")

    def scripted(*, rule_id, candidate_file_source, source_file_name):
        if "MD5" in candidate_file_source:
            return [{"violation_id": rule_id, "rule_id": rule_id, "reason": "tainted"}]
        return []

    monkeypatch.setattr(scoped_verification, "get_engine", lambda _name: _fake_engine(scripted))
    monkeypatch.setattr(scoped_verification, "evidence_source_for_rule_id", lambda _rule_id: "opengrep")

    result = verify_candidate(
        workspace_root=tmp_path,
        source=source,
        method_selector="demo.Crypto#hash()",
        candidate=candidate,
        rule_id="ISO-A.8-CMD-INJECTION",
        expected_source_sha256=sha256_hex(source.read_bytes()),
        work_dir=tmp_path / "work",
    )
    assert result["status"] == "POLICY_PASS"
    assert result["policy_status"] == "PASS"
    assert result["engine"]["name"] == "opengrep"


def test_scoped_verification_opengrep_baseline_not_detected_fails_closed(monkeypatch, tmp_path) -> None:
    from codegraph.remediation import scoped_verification

    source, candidate = _write_case(tmp_path, BASE_SOURCE, "public void hash() {}")

    monkeypatch.setattr(scoped_verification, "get_engine", lambda _name: _fake_engine(lambda **_kwargs: []))
    monkeypatch.setattr(scoped_verification, "evidence_source_for_rule_id", lambda _rule_id: "opengrep")

    result = verify_candidate(
        workspace_root=tmp_path,
        source=source,
        method_selector="demo.Crypto#hash()",
        candidate=candidate,
        rule_id="ISO-A.8-CMD-INJECTION",
        expected_source_sha256=sha256_hex(source.read_bytes()),
        work_dir=tmp_path / "work",
    )
    assert result["status"] == "NOT_EVALUATED"
    assert result["error"] == "baseline_target_rule_not_detected"


def test_scoped_verification_opengrep_engine_error_fails_closed(monkeypatch, tmp_path) -> None:
    from codegraph.remediation import scoped_verification

    source, candidate = _write_case(tmp_path, BASE_SOURCE, "public void hash() {}")

    def raises(**_kwargs):
        raise RuntimeError("opengrep_unavailable")

    monkeypatch.setattr(scoped_verification, "get_engine", lambda _name: _fake_engine(raises))
    monkeypatch.setattr(scoped_verification, "evidence_source_for_rule_id", lambda _rule_id: "opengrep")

    result = verify_candidate(
        workspace_root=tmp_path,
        source=source,
        method_selector="demo.Crypto#hash()",
        candidate=candidate,
        rule_id="ISO-A.8-CMD-INJECTION",
        expected_source_sha256=sha256_hex(source.read_bytes()),
        work_dir=tmp_path / "work",
    )
    assert result["status"] == "ENGINE_ERROR"
    assert result["policy_status"] == "ERROR"


@pytest.mark.skipif(not OPA_AVAILABLE, reason="opa binary not found on PATH")
def test_scoped_verification_reports_policy_pass_without_build_or_graph(monkeypatch, tmp_path) -> None:
    root = tmp_path / "policy-pass"
    root.mkdir()
    source_path, candidate_path = _write_case(
        root,
        BASE_SOURCE,
        """  public void hash() throws java.security.NoSuchAlgorithmException {
    java.security.MessageDigest.getInstance("SHA-256");
  }
""",
    )

    import codegraph.db as db
    import codegraph.remediation.verification as build_verification

    def forbidden(*_args, **_kwargs):
        raise AssertionError("scoped verification must not access graph or ingestion writes")

    monkeypatch.setattr(db, "shared_neo4j_driver", forbidden)
    monkeypatch.setattr(build_verification, "compile_project", forbidden)
    original_bytes = source_path.read_bytes()

    result = verify_candidate(
        workspace_root=root,
        source=source_path.relative_to(root),
        method_selector="demo.Crypto#hash()",
        candidate=candidate_path,
        rule_id="ISO-A.10-WEAK-HASH",
        expected_source_sha256=sha256_hex(source_path.read_bytes()),
        work_dir=root / ".work",
    )

    assert result["status"] == "POLICY_PASS"
    assert result["policy_status"] == "PASS"
    assert result["build_status"] == "NOT_EVALUATED"
    assert result["build_reason"] == "governed_build_worker_unavailable"
    assert result["scope"] == "target_method_only"
    assert result["affected_callers_status"] == "NOT_EVALUATED"
    assert result["target_rule_status"] == "PASS"
    assert result["engine"]["name"] == "opa"
    assert result["baseline"]["source_sha256"] == sha256_hex(source_path.read_bytes())
    assert result["candidate"]["source_sha256"] != result["baseline"]["source_sha256"]
    assert source_path.read_bytes() == original_bytes


@pytest.mark.skipif(not OPA_AVAILABLE, reason="opa binary not found on PATH")
def test_scoped_verification_rejects_stale_source_and_policy_before_opa(monkeypatch, tmp_path) -> None:
    root = tmp_path / "stale"
    root.mkdir()
    source_path, candidate_path = _write_case(root, BASE_SOURCE, "public void hash() {}\n")

    import codegraph.policy.runtime.opa as opa_runtime

    def forbidden(*_args, **_kwargs):
        raise AssertionError("stale candidate must be rejected before OPA evaluation")

    monkeypatch.setattr(opa_runtime, "evaluate_bundle", forbidden)

    stale_source = verify_candidate(
        workspace_root=root,
        source=source_path.relative_to(root),
        method_selector="demo.Crypto#hash()",
        candidate=candidate_path,
        rule_id="ISO-A.10-WEAK-HASH",
        expected_source_sha256="0" * 64,
        work_dir=root / ".work",
    )
    assert stale_source["status"] == "STALE_CANDIDATE"
    assert "source_sha256_mismatch" in stale_source["stale_reasons"]

    stale_policy = verify_candidate(
        workspace_root=root,
        source=source_path.relative_to(root),
        method_selector="demo.Crypto#hash()",
        candidate=candidate_path,
        rule_id="ISO-A.10-WEAK-HASH",
        expected_source_sha256=sha256_hex(source_path.read_bytes()),
        expected_policy_sha256="0" * 64,
        work_dir=root / ".work-policy",
    )
    assert stale_policy["status"] == "STALE_CANDIDATE"
    assert "policy_sha256_mismatch" in stale_policy["stale_reasons"]


@pytest.mark.skipif(not OPA_AVAILABLE, reason="opa binary not found on PATH")
def test_scoped_verification_reports_policy_fail_and_invalid_candidate(tmp_path) -> None:
    root = tmp_path / "policy-fail"
    root.mkdir()
    source_path, candidate_path = _write_case(
        root, BASE_SOURCE, BASE_SOURCE.split("class Crypto {\n", 1)[1].rsplit("}\n", 1)[0]
    )

    failed = verify_candidate(
        workspace_root=root,
        source=source_path.relative_to(root),
        method_selector="demo.Crypto#hash()",
        candidate=candidate_path,
        rule_id="ISO-A.10-WEAK-HASH",
        expected_source_sha256=sha256_hex(source_path.read_bytes()),
        work_dir=root / ".work",
    )
    assert failed["status"] == "POLICY_FAIL"
    assert failed["target_rule_status"] == "FAIL"

    bad_candidate = root / "bad.java"
    bad_candidate.write_text("public void nope() {}\n", encoding="utf-8")
    invalid = verify_candidate(
        workspace_root=root,
        source=source_path.relative_to(root),
        method_selector="demo.Crypto#hash()",
        candidate=bad_candidate,
        rule_id="ISO-A.10-WEAK-HASH",
        expected_source_sha256=sha256_hex(source_path.read_bytes()),
        work_dir=root / ".work-invalid",
    )
    assert invalid["status"] == "INVALID_CANDIDATE"
    assert invalid["policy_status"] == "NOT_EVALUATED"


@pytest.mark.skipif(not OPA_AVAILABLE, reason="opa binary not found on PATH")
def test_scoped_verification_reports_opa_error_for_captured_bad_policy(tmp_path) -> None:
    root = tmp_path / "opa-error"
    root.mkdir()
    source_path, candidate_path = _write_case(root, BASE_SOURCE, "  public void hash() {\n  }\n")
    bad_policy = root / "policy"
    bad_policy.mkdir()
    (bad_policy / "bad.rego").write_text("package iso27001\n\nviolations if {\n", encoding="utf-8")

    result = verify_candidate(
        workspace_root=root,
        source=source_path.relative_to(root),
        method_selector="demo.Crypto#hash()",
        candidate=candidate_path,
        rule_id="ISO-A.10-WEAK-HASH",
        expected_source_sha256=sha256_hex(source_path.read_bytes()),
        policy_dir=bad_policy,
        work_dir=root / ".work",
    )

    assert result["status"] == "OPA_ERROR"
    assert result["policy_status"] == "ERROR"


@pytest.mark.skipif(not OPA_AVAILABLE, reason="opa binary not found on PATH")
def test_scoped_verification_cleans_policy_capture_on_empty_policy_error(tmp_path) -> None:
    root = tmp_path / "empty-policy"
    root.mkdir()
    source_path, candidate_path = _write_case(root, BASE_SOURCE, "  public void hash() {\n  }\n")
    empty_policy = root / "policy"
    empty_policy.mkdir()
    work_dir = root / ".work"

    result = verify_candidate(
        workspace_root=root,
        source=source_path.relative_to(root),
        method_selector="demo.Crypto#hash()",
        candidate=candidate_path,
        rule_id="ISO-A.10-WEAK-HASH",
        expected_source_sha256=sha256_hex(source_path.read_bytes()),
        policy_dir=empty_policy,
        work_dir=work_dir,
    )

    assert result["status"] == "OPA_ERROR"
    assert list(work_dir.iterdir()) == []


@pytest.mark.skipif(not OPA_AVAILABLE, reason="opa binary not found on PATH")
def test_scoped_verification_refuses_unknown_or_absent_baseline_rule(monkeypatch, tmp_path) -> None:
    root = tmp_path / "unknown-rule"
    root.mkdir()
    source_path, candidate_path = _write_case(root, BASE_SOURCE, "  public void hash() {\n  }\n")

    unknown = verify_candidate(
        workspace_root=root,
        source=source_path.relative_to(root),
        method_selector="demo.Crypto#hash()",
        candidate=candidate_path,
        rule_id="NOT-A-REAL-RULE",
        expected_source_sha256=sha256_hex(source_path.read_bytes()),
        work_dir=root / ".work-unknown",
    )
    assert unknown["status"] == "NOT_EVALUATED"
    assert unknown["policy_status"] == "NOT_EVALUATED"
    assert unknown["error"] == "unknown_rule_id"

    import codegraph.policy.runtime.opa as opa_runtime

    monkeypatch.setattr(opa_runtime, "evaluate_bundle", lambda *_args, **_kwargs: [])
    absent = verify_candidate(
        workspace_root=root,
        source=source_path.relative_to(root),
        method_selector="demo.Crypto#hash()",
        candidate=candidate_path,
        rule_id="ISO-A.10-WEAK-HASH",
        expected_source_sha256=sha256_hex(source_path.read_bytes()),
        work_dir=root / ".work-absent",
    )
    assert absent["status"] == "NOT_EVALUATED"
    assert absent["error"] == "baseline_target_rule_not_detected"


@pytest.mark.skipif(not OPA_AVAILABLE, reason="opa binary not found on PATH")
def test_scoped_verification_invalid_finding_is_opa_error(monkeypatch, tmp_path) -> None:
    root = tmp_path / "invalid-finding"
    root.mkdir()
    source_path, candidate_path = _write_case(root, BASE_SOURCE, "  public void hash() {\n  }\n")

    import codegraph.policy.runtime.opa as opa_runtime

    monkeypatch.setattr(opa_runtime, "evaluate_bundle", lambda *_args, **_kwargs: [{}])
    result = verify_candidate(
        workspace_root=root,
        source=source_path.relative_to(root),
        method_selector="demo.Crypto#hash()",
        candidate=candidate_path,
        rule_id="ISO-A.10-WEAK-HASH",
        expected_source_sha256=sha256_hex(source_path.read_bytes()),
        work_dir=root / ".work",
    )

    assert result["status"] == "OPA_ERROR"
    assert result["policy_status"] == "ERROR"
    assert result["error"] == "OPA returned an invalid violation"


@pytest.mark.skipif(not OPA_AVAILABLE, reason="opa binary not found on PATH")
def test_scoped_verification_reports_structured_input_errors(tmp_path) -> None:
    root = tmp_path / "input-errors"
    root.mkdir()
    source_path, candidate_path = _write_case(root, BASE_SOURCE, "  public void hash() {\n  }\n")

    outside = verify_candidate(
        workspace_root=root,
        source="../outside.java",
        method_selector="demo.Crypto#hash()",
        candidate=candidate_path,
        rule_id="ISO-A.10-WEAK-HASH",
        expected_source_sha256=sha256_hex(source_path.read_bytes()),
        work_dir=root / ".work-outside",
    )
    assert outside["status"] == "INPUT_ERROR"
    assert outside["error"] == "source_path_outside_workspace"

    missing_candidate = verify_candidate(
        workspace_root=root,
        source=source_path.relative_to(root),
        method_selector="demo.Crypto#hash()",
        candidate=root / "missing.java",
        rule_id="ISO-A.10-WEAK-HASH",
        expected_source_sha256=sha256_hex(source_path.read_bytes()),
        work_dir=root / ".work-missing",
    )
    assert missing_candidate["status"] == "INPUT_ERROR"
    assert missing_candidate["error"] == "candidate_file_unavailable"


@pytest.mark.skipif(not OPA_AVAILABLE, reason="opa binary not found on PATH")
def test_scoped_verification_reports_disappearing_source_and_candidate_reads(monkeypatch, tmp_path) -> None:
    root = tmp_path / "disappearing-inputs"
    root.mkdir()
    source_path, candidate_path = _write_case(root, BASE_SOURCE, "  public void hash() {\n  }\n")
    original_read_bytes = Path.read_bytes

    def source_disappears(path: Path) -> bytes:
        if path == source_path:
            raise FileNotFoundError("source disappeared")
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", source_disappears)
    source_result = verify_candidate(
        workspace_root=root,
        source=source_path.relative_to(root),
        method_selector="demo.Crypto#hash()",
        candidate=candidate_path,
        rule_id="ISO-A.10-WEAK-HASH",
        expected_source_sha256=sha256_hex(BASE_SOURCE.encode("utf-8")),
        work_dir=root / ".work-source",
    )
    assert source_result["status"] == "INPUT_ERROR"
    assert "source disappeared" in source_result["error"]

    monkeypatch.setattr(Path, "read_bytes", original_read_bytes)

    def candidate_disappears(path: Path) -> bytes:
        if path == candidate_path:
            raise FileNotFoundError("candidate disappeared")
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", candidate_disappears)
    candidate_result = verify_candidate(
        workspace_root=root,
        source=source_path.relative_to(root),
        method_selector="demo.Crypto#hash()",
        candidate=candidate_path,
        rule_id="ISO-A.10-WEAK-HASH",
        expected_source_sha256=sha256_hex(source_path.read_text(encoding="utf-8").encode("utf-8")),
        work_dir=root / ".work-candidate",
    )
    assert candidate_result["status"] == "INPUT_ERROR"
    assert "candidate disappeared" in candidate_result["error"]


@pytest.mark.skipif(not OPA_AVAILABLE, reason="opa binary not found on PATH")
def test_policy_copy_read_error_returns_opa_error_and_cleans_capture(monkeypatch, tmp_path) -> None:
    root = tmp_path / "copy-error"
    root.mkdir()
    source_path, candidate_path = _write_case(root, BASE_SOURCE, "  public void hash() {\n  }\n")
    policy_dir = root / "policy"
    policy_dir.mkdir()
    (policy_dir / "catalog.json").write_text('{"controls":[]}', encoding="utf-8")
    work_dir = root / ".work"
    original_read_bytes = Path.read_bytes

    def policy_read_fails(path: Path) -> bytes:
        if path == policy_dir / "catalog.json":
            raise OSError("policy copy failed")
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", policy_read_fails)
    result = verify_candidate(
        workspace_root=root,
        source=source_path.relative_to(root),
        method_selector="demo.Crypto#hash()",
        candidate=candidate_path,
        rule_id="ISO-A.10-WEAK-HASH",
        expected_source_sha256=sha256_hex(source_path.read_bytes()),
        policy_dir=policy_dir,
        work_dir=work_dir,
    )

    assert result["status"] == "OPA_ERROR"
    assert "policy copy failed" in result["error"]
    assert list(work_dir.iterdir()) == []


@pytest.mark.skipif(not OPA_AVAILABLE, reason="opa binary not found on PATH")
@pytest.mark.parametrize("stale_source", [False, True])
def test_cleanup_failure_preserves_primary_report_and_blocks_policy_pass(monkeypatch, tmp_path, stale_source) -> None:
    root = tmp_path / "cleanup-error"
    root.mkdir()
    source_path, candidate_path = _write_case(root, BASE_SOURCE, "  public void hash() {\n  }\n")

    class FailingTemporaryDirectory:
        def __init__(self, *, prefix: str, dir: Path):
            self.name = str(Path(dir) / f"{prefix}fixed")

        def __enter__(self) -> str:
            Path(self.name).mkdir(parents=True)
            return self.name

        def __exit__(self, exc_type, exc, tb) -> bool:
            raise PermissionError("cleanup denied")

    import codegraph.remediation.scoped_verification as scoped

    real_temporary_directory = scoped.tempfile.TemporaryDirectory

    def temporary_directory(*, prefix: str, dir: Path):
        if prefix == "policy-capture-":
            return FailingTemporaryDirectory(prefix=prefix, dir=dir)
        return real_temporary_directory(prefix=prefix, dir=dir)

    monkeypatch.setattr(scoped.tempfile, "TemporaryDirectory", temporary_directory)
    result = verify_candidate(
        workspace_root=root,
        source=source_path.relative_to(root),
        method_selector="demo.Crypto#hash()",
        candidate=candidate_path,
        rule_id="ISO-A.10-WEAK-HASH",
        expected_source_sha256="0" * 64 if stale_source else sha256_hex(source_path.read_bytes()),
        work_dir=root / ".work",
    )

    assert result["status"] == ("STALE_CANDIDATE" if stale_source else "CLEANUP_ERROR")
    assert result["primary_status"] == ("STALE_CANDIDATE" if stale_source else "POLICY_PASS")
    assert result["policy_status"] == ("NOT_EVALUATED" if stale_source else "PASS")
    assert result["cleanup_error"] == "cleanup denied"


@pytest.mark.skipif(not OPA_AVAILABLE, reason="opa binary not found on PATH")
def test_verify_candidate_cli_exit_codes_and_json_report(tmp_path) -> None:
    root = tmp_path / "cli"
    root.mkdir()
    source_path, candidate_path = _write_case(root, BASE_SOURCE, "  public void hash() {\n  }\n")
    cmd = [
        sys.executable,
        "-m",
        "scripts.remediation.verify_candidate",
        "--workspace-root",
        str(root),
        "--source",
        str(source_path.relative_to(root)),
        "--method",
        "demo.Crypto#hash()",
        "--candidate",
        str(candidate_path),
        "--rule-id",
        "ISO-A.10-WEAK-HASH",
        "--expected-source-sha256",
        sha256_hex(source_path.read_bytes()),
        "--work-dir",
        str(root / ".work"),
    ]

    proc = subprocess.run(cmd, cwd=Path.cwd(), capture_output=True, text=True, check=False)

    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["status"] == "POLICY_PASS"
    assert payload["build_status"] == "NOT_EVALUATED"

    stale = subprocess.run(
        [*cmd[:-3], "0" * 64, "--work-dir", str(root / ".work-stale")],
        cwd=Path.cwd(),
        capture_output=True,
        text=True,
        check=False,
    )
    assert stale.returncode != 0
    assert json.loads(stale.stdout)["status"] == "STALE_CANDIDATE"
