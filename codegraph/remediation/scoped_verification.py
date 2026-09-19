from __future__ import annotations

import logging
import tempfile
from pathlib import Path
from typing import Any

from codegraph.benchmark_registry import evidence_source_for_rule_id
from codegraph.ingestion.snapshots import (
    AmbiguousMethodError,
    SnapshotError,
    StaleSourceError,
    UnsupportedSourceError,
    create_source_snapshot,
)
from codegraph.policy.engines import get_engine
from codegraph.policy.runtime import opa as opa_runtime
from codegraph.remediation.candidate import InvalidCandidateError, build_candidate_overlay
from codegraph.remediation.scoped_verification_engine import verify_candidate_via_engine
from codegraph.remediation.scoped_verification_opa import (
    _catalog_rule_ids,
    _copy_and_fingerprint_policy,
    _ids,
    _normalize_findings,
    _opa_version,
    _snapshot_to_bundle,
)
from codegraph.remediation.scoped_verification_types import (
    CapturedPolicyInputs,
    PolicyFingerprint,
    _attach_cleanup_error,
    _identity_dict,
    _resolve_candidate,
    _resolve_source,
    _status,
)
from codegraph.remediation.verification import build_verification_summary

__all__ = [
    "CapturedPolicyInputs",
    "PolicyFingerprint",
    "_opa_version",
    "verify_candidate",
]

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_POLICY_DIR = _PROJECT_ROOT / "policy"
LOGGER = logging.getLogger(__name__)


def verify_candidate(
    *,
    workspace_root: str | Path,
    source: str | Path,
    method_selector: str,
    candidate: str | Path,
    rule_id: str,
    expected_source_sha256: str,
    expected_policy_sha256: str | None = None,
    policy_dir: str | Path | None = None,
    work_dir: str | Path | None = None,
) -> dict[str, Any]:
    workspace = Path(workspace_root)
    try:
        source_path = _resolve_source(workspace, source)
        candidate_path = _resolve_candidate(workspace, candidate)
    except (SnapshotError, FileNotFoundError, OSError) as exc:
        return _status("INPUT_ERROR", rule_id=rule_id, error=str(exc))

    engine = get_engine(evidence_source_for_rule_id(rule_id))
    if engine is not None:
        return verify_candidate_via_engine(
            engine,
            workspace=workspace,
            source_path=source_path,
            candidate_path=candidate_path,
            method_selector=method_selector,
            rule_id=rule_id,
            expected_source_sha256=expected_source_sha256,
        )

    scratch = Path(work_dir) if work_dir else Path.cwd() / "build" / "scoped-verification-work"
    try:
        scratch.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return _status("INPUT_ERROR", rule_id=rule_id, error=str(exc))
    try:
        tempdir = tempfile.TemporaryDirectory(prefix="policy-capture-", dir=scratch)
    except OSError as exc:
        return _status("INPUT_ERROR", rule_id=rule_id, error=str(exc))
    report: dict[str, Any] | None = None
    try:
        try:
            capture_root = Path(tempdir.__enter__())
        except OSError as exc:
            report = _status("INPUT_ERROR", rule_id=rule_id, error=str(exc))
            return report
        try:
            baseline = create_source_snapshot(
                workspace_root=workspace,
                source_path=source_path,
                method_selector=method_selector,
                expected_source_sha256=expected_source_sha256,
            )
        except StaleSourceError:
            report = _status("STALE_CANDIDATE", rule_id=rule_id, stale_reasons=["source_sha256_mismatch"])
            return report
        except AmbiguousMethodError as exc:
            report = _status("AMBIGUOUS_METHOD", rule_id=rule_id, error=str(exc))
            return report
        except UnsupportedSourceError as exc:
            report = _status("UNSUPPORTED_SOURCE", rule_id=rule_id, error=str(exc))
            return report
        except (SnapshotError, OSError) as exc:
            report = _status("INPUT_ERROR", rule_id=rule_id, error=str(exc))
            return report

        try:
            captured = _copy_and_fingerprint_policy(
                Path(policy_dir) if policy_dir else _DEFAULT_POLICY_DIR, capture_root
            )
            valid_rule_ids = _catalog_rule_ids(captured.source_dir)
        except (RuntimeError, OSError, UnicodeError) as exc:
            report = _status("OPA_ERROR", rule_id=rule_id, policy_status="ERROR", error=str(exc))
            return report
        if expected_policy_sha256 and expected_policy_sha256 != captured.fingerprint.policy_sha256:
            report = _status(
                "STALE_CANDIDATE",
                rule_id=rule_id,
                stale_reasons=["policy_sha256_mismatch"],
                extra={"policy_fingerprint": captured.fingerprint.to_dict()},
            )
            return report
        if rule_id not in valid_rule_ids:
            report = _status(
                "NOT_EVALUATED",
                rule_id=rule_id,
                error="unknown_rule_id",
                extra={"policy_fingerprint": captured.fingerprint.to_dict()},
            )
            return report

        try:
            candidate_bytes = candidate_path.read_bytes()
        except OSError as exc:
            report = _status("INPUT_ERROR", rule_id=rule_id, error=str(exc))
            return report
        try:
            overlay = build_candidate_overlay(baseline, candidate_bytes)
        except InvalidCandidateError as exc:
            report = _status(
                "INVALID_CANDIDATE",
                rule_id=rule_id,
                error=str(exc),
                extra={"policy_fingerprint": captured.fingerprint.to_dict()},
            )
            return report

        baseline_bundle = _snapshot_to_bundle(baseline, file_bytes=baseline.full_file_bytes)
        candidate_bundle = _snapshot_to_bundle(overlay.candidate_snapshot, file_bytes=overlay.candidate_file_bytes)
        try:
            baseline_findings = _normalize_findings(
                opa_runtime.evaluate_bundle(
                    baseline_bundle,
                    policy_dir=captured.source_dir.as_posix(),
                    work_dir=captured.source_dir.parent.as_posix(),
                )
            )
            candidate_findings = _normalize_findings(
                opa_runtime.evaluate_bundle(
                    candidate_bundle,
                    policy_dir=captured.source_dir.as_posix(),
                    work_dir=captured.source_dir.parent.as_posix(),
                )
            )
        except (RuntimeError, OSError) as exc:
            report = _status(
                "OPA_ERROR",
                rule_id=rule_id,
                policy_status="ERROR",
                error=str(exc),
                extra={"policy_fingerprint": captured.fingerprint.to_dict()},
            )
            return report
        if rule_id not in _ids(baseline_findings):
            report = _status(
                "NOT_EVALUATED",
                rule_id=rule_id,
                error="baseline_target_rule_not_detected",
                extra={
                    "policy_fingerprint": captured.fingerprint.to_dict(),
                    "engine": {
                        "name": captured.fingerprint.engine_name,
                        "version": captured.fingerprint.engine_version,
                    },
                    "findings": {"baseline": baseline_findings, "candidate": candidate_findings},
                },
            )
            return report
        summary = build_verification_summary(rule_id, baseline_findings, candidate_findings)
        target_rule_status = summary["target_rule_status"]
        new_rule_ids = sorted(_ids(candidate_findings) - _ids(baseline_findings))
        status = "POLICY_PASS" if target_rule_status == "PASS" and not new_rule_ids else "POLICY_FAIL"
        policy_summary = {
            "target_rule_status": target_rule_status,
            "new_violations": summary["new_violations"],
            "remaining_baseline_violations": summary["remaining_violations"],
        }
        report = _status(
            status,
            rule_id=rule_id,
            policy_status="PASS" if status == "POLICY_PASS" else "FAIL",
            extra={
                "target_rule_status": target_rule_status,
                "baseline": {
                    "source_sha256": baseline.file_sha256,
                    "method_sha256": baseline.method_sha256,
                    "identity": _identity_dict(baseline.identity),
                },
                "candidate": {
                    "source_sha256": overlay.candidate_file_sha256,
                    "method_sha256": overlay.candidate_method_sha256,
                    "identity": _identity_dict(overlay.candidate_snapshot.identity),
                },
                "policy_fingerprint": captured.fingerprint.to_dict(),
                "engine": {"name": captured.fingerprint.engine_name, "version": captured.fingerprint.engine_version},
                "findings": {"baseline": baseline_findings, "candidate": candidate_findings},
                "rule_delta": {
                    "removed": sorted(_ids(baseline_findings) - _ids(candidate_findings)),
                    "added": new_rule_ids,
                    "unchanged": sorted(_ids(baseline_findings) & _ids(candidate_findings)),
                },
                "policy_summary": policy_summary,
            },
        )
        return report
    finally:
        try:
            tempdir.__exit__(None, None, None)
        except OSError as exc:
            if report is None:
                raise
            updated = _attach_cleanup_error(report, exc)
            report.clear()
            report.update(updated)
