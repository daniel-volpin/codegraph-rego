from __future__ import annotations

from pathlib import Path
from typing import Any

from codegraph.ingestion.snapshots import (
    AmbiguousMethodError,
    SnapshotError,
    StaleSourceError,
    UnsupportedSourceError,
    create_source_snapshot,
)
from codegraph.policy.engines import DetectionEngine
from codegraph.remediation.candidate import InvalidCandidateError, build_candidate_overlay
from codegraph.remediation.scoped_verification_opa import _ids
from codegraph.remediation.scoped_verification_types import _identity_dict, _status
from codegraph.remediation.verification import build_verification_summary


def verify_candidate_via_engine(
    engine: DetectionEngine,
    *,
    workspace: Path,
    source_path: Path,
    candidate_path: Path,
    method_selector: str,
    rule_id: str,
    expected_source_sha256: str,
) -> dict[str, Any]:
    """Re-check *rule_id* through its owning non-OPA engine (e.g. OpenGrep)."""
    try:
        baseline = create_source_snapshot(
            workspace_root=workspace,
            source_path=source_path,
            method_selector=method_selector,
            expected_source_sha256=expected_source_sha256,
        )
    except StaleSourceError:
        return _status(status="STALE_CANDIDATE", rule_id=rule_id, stale_reasons=["source_sha256_mismatch"])
    except AmbiguousMethodError as exc:
        return _status("AMBIGUOUS_METHOD", rule_id=rule_id, error=str(exc))
    except UnsupportedSourceError as exc:
        return _status("UNSUPPORTED_SOURCE", rule_id=rule_id, error=str(exc))
    except (SnapshotError, OSError) as exc:
        return _status("INPUT_ERROR", rule_id=rule_id, error=str(exc))

    if rule_id not in engine.discover_rule_ids():
        return _status("NOT_EVALUATED", rule_id=rule_id, error="unknown_rule_id")

    try:
        candidate_bytes = candidate_path.read_bytes()
    except OSError as exc:
        return _status("INPUT_ERROR", rule_id=rule_id, error=str(exc))
    try:
        overlay = build_candidate_overlay(baseline, candidate_bytes)
    except InvalidCandidateError as exc:
        return _status("INVALID_CANDIDATE", rule_id=rule_id, error=str(exc))

    try:
        baseline_findings = engine.verify_candidate(
            rule_id=rule_id,
            candidate_file_source=baseline.full_file_bytes.decode("utf-8"),
            source_file_name=source_path.name,
        )
        candidate_findings = engine.verify_candidate(
            rule_id=rule_id,
            candidate_file_source=overlay.candidate_file_bytes.decode("utf-8"),
            source_file_name=source_path.name,
        )
    except RuntimeError as exc:
        return _status("ENGINE_ERROR", rule_id=rule_id, policy_status="ERROR", error=str(exc))

    if rule_id not in _ids(baseline_findings):
        return _status(
            "NOT_EVALUATED",
            rule_id=rule_id,
            error="baseline_target_rule_not_detected",
            extra={
                "engine": {"name": engine.name},
                "findings": {"baseline": baseline_findings, "candidate": candidate_findings},
            },
        )

    summary = build_verification_summary(rule_id, baseline_findings, candidate_findings)
    target_rule_status = summary["target_rule_status"]
    new_rule_ids = sorted(_ids(candidate_findings) - _ids(baseline_findings))
    status = "POLICY_PASS" if target_rule_status == "PASS" and not new_rule_ids else "POLICY_FAIL"
    return _status(
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
            "engine": {"name": engine.name},
            "findings": {"baseline": baseline_findings, "candidate": candidate_findings},
            "rule_delta": {
                "removed": sorted(_ids(baseline_findings) - _ids(candidate_findings)),
                "added": new_rule_ids,
                "unchanged": sorted(_ids(baseline_findings) & _ids(candidate_findings)),
            },
            "policy_summary": {
                "target_rule_status": target_rule_status,
                "new_violations": summary["new_violations"],
                "remaining_baseline_violations": summary["remaining_violations"],
            },
        },
    )
