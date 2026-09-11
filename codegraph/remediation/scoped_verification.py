from __future__ import annotations

import hashlib
import json
import logging
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from codegraph.ingestion.snapshots import (
    AmbiguousMethodError,
    MethodIdentity,
    SharedLineReplacementError,
    SnapshotError,
    SourceSnapshot,
    StaleSourceError,
    UnsupportedSourceError,
    create_source_snapshot,
    sha256_hex,
)
from codegraph.policy.runtime import opa as opa_runtime
from codegraph.policy.runtime.bundles import build_evidence_bundle_from_source
from codegraph.remediation.candidate import InvalidCandidateError, build_candidate_overlay
from codegraph.remediation.context import build_virtual_graph_context
from codegraph.remediation.verification import build_verification_summary

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_POLICY_DIR = _PROJECT_ROOT / "policy"
LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class PolicyFingerprint:
    policy_sha256: str
    engine_name: str
    engine_version: str
    files: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_sha256": self.policy_sha256,
            "engine": {"name": self.engine_name, "version": self.engine_version},
            "files": list(self.files),
        }


@dataclass(frozen=True)
class CapturedPolicyInputs:
    source_dir: Path
    fingerprint: PolicyFingerprint


def _status(
    status: str,
    *,
    rule_id: str,
    stale_reasons: list[str] | None = None,
    error: str | None = None,
    policy_status: str = "NOT_EVALUATED",
    build_status: str = "NOT_EVALUATED",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = {
        "status": status,
        "policy_status": policy_status,
        "build_status": build_status,
        "build_reason": "governed_build_worker_unavailable",
        "scope": "target_method_only",
        "affected_callers_status": "NOT_EVALUATED",
        "target_rule_status": "UNKNOWN",
        "rule_id": rule_id,
        "stale_reasons": stale_reasons or [],
        "error": error,
    }
    if extra:
        payload.update(extra)
    return payload


def _attach_cleanup_error(report: dict[str, Any], exc: BaseException) -> dict[str, Any]:
    result = dict(report)
    primary_status = str(result.get("status") or "")
    result["primary_status"] = primary_status
    result["cleanup_error"] = str(exc)
    if primary_status == "POLICY_PASS":
        result["status"] = "CLEANUP_ERROR"
        result["policy_status"] = "PASS"
    return result


def _resolve_source(workspace_root: Path, source: str | Path) -> Path:
    root = workspace_root.resolve()
    candidate = (root / Path(source)).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise SnapshotError("source_path_outside_workspace") from exc
    if not candidate.is_file():
        raise FileNotFoundError("source_file_unavailable")
    return candidate


def _resolve_candidate(workspace_root: Path, candidate: str | Path) -> Path:
    root = workspace_root.resolve()
    raw = Path(candidate)
    path = raw.resolve() if raw.is_absolute() else (root / raw).resolve()
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise SnapshotError("candidate_path_outside_workspace") from exc
    if not path.is_file():
        raise FileNotFoundError("candidate_file_unavailable")
    return path


def _opa_version() -> str:
    try:
        proc = subprocess.run(["opa", "version"], capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"opa_version_unavailable: {exc}") from exc
    if proc.returncode != 0:
        raise RuntimeError(f"opa_version_unavailable: {proc.stderr.strip()}")
    for line in proc.stdout.splitlines():
        if line.startswith("Version:"):
            version = line.split(":", 1)[1].strip()
            if version:
                return version
    raise RuntimeError("opa_version_unavailable")


def _policy_files(policy_dir: Path) -> tuple[Path, ...]:
    files = [
        path
        for path in policy_dir.rglob("*")
        if path.is_file() and path.suffix.lower() in {".rego", ".json", ".yaml", ".yml"}
    ]
    return tuple(sorted(files, key=lambda path: path.relative_to(policy_dir).as_posix()))


def _copy_and_fingerprint_policy(policy_dir: Path, capture_root: Path) -> CapturedPolicyInputs:
    if not policy_dir.is_dir():
        raise RuntimeError("policy_dir_unavailable")
    engine_version = _opa_version()
    capture_dir = capture_root / "policy"
    capture_dir.mkdir(parents=True)
    digest = hashlib.sha256()
    relative_files: list[str] = []
    for source_file in _policy_files(policy_dir):
        rel = source_file.relative_to(policy_dir)
        relative = rel.as_posix()
        target = capture_dir / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        data = source_file.read_bytes()
        target.write_bytes(data)
        relative_files.append(relative)
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(data)
        digest.update(b"\0")
    if not relative_files:
        raise RuntimeError("policy_dir_empty")
    return CapturedPolicyInputs(
        source_dir=capture_dir,
        fingerprint=PolicyFingerprint(
            policy_sha256=digest.hexdigest(),
            engine_name="opa",
            engine_version=engine_version,
            files=tuple(relative_files),
        ),
    )


def _catalog_rule_ids(captured_policy_dir: Path) -> set[str]:
    catalog_path = captured_policy_dir / "catalog.json"
    if not catalog_path.is_file():
        raise RuntimeError("policy_catalog_unavailable")
    try:
        raw = json.loads(catalog_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise RuntimeError("policy_catalog_invalid") from exc
    controls = raw.get("controls") if isinstance(raw, dict) else None
    if not isinstance(controls, list):
        raise RuntimeError("policy_catalog_invalid")
    ids = {str(item.get("id")) for item in controls if isinstance(item, dict) and item.get("id")}
    if not ids:
        raise RuntimeError("policy_catalog_empty")
    return ids


def _snapshot_to_bundle(snapshot: SourceSnapshot, *, file_bytes: bytes) -> dict[str, Any]:
    graph = build_virtual_graph_context(snapshot.method_source, base_graph={})
    method_snapshot = {
        "signature": snapshot.identity.syntactic_signature,
        "name": snapshot.identity.name,
        "class_fqn": snapshot.identity.declaring_type,
        "file_path": snapshot.identity.workspace_relative_path,
        "start_line": snapshot.start_line,
        "end_line": snapshot.end_line,
        "modifiers": list(snapshot.modifiers),
        "annotations": sorted({*snapshot.annotations, *(graph.get("annotations") or [])}),
        "uses_fields": graph.get("uses_fields") or [],
        "calls": graph.get("calls") or [],
        "callers": [],
    }
    return build_evidence_bundle_from_source(
        method_snapshot,
        snapshot.method_source,
        vector_context=[],
        bundle_file_path=snapshot.identity.workspace_relative_path,
    ) | {"file_sha256": sha256_hex(file_bytes), "method_sha256": snapshot.method_sha256}


def _normalize_findings(raw_findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for finding in raw_findings:
        value = opa_runtime.normalize_violation_payload(finding, LOGGER)
        if value is None or not isinstance(value.get("violation_id"), str) or not value.get("violation_id"):
            raise RuntimeError("OPA returned an invalid violation")
        normalized.append(value)
    return sorted(normalized, key=lambda item: (str(item.get("violation_id")), str(item.get("reason"))))


def _ids(findings: list[dict[str, Any]]) -> set[str]:
    return {str(item.get("violation_id")) for item in findings if item.get("violation_id")}


def _identity_dict(identity: MethodIdentity) -> dict[str, Any]:
    return {
        "workspace_relative_path": identity.workspace_relative_path,
        "declaring_type": identity.declaring_type,
        "name": identity.name,
        "parameters": [
            {
                "type_name": param.type_name,
                "array_dimensions": param.array_dimensions,
                "varargs": param.varargs,
            }
            for param in identity.parameters
        ],
        "is_constructor": identity.is_constructor,
        "selector": identity.selector,
        "legacy_signature": identity.legacy_signature,
        "syntactic_signature": identity.syntactic_signature,
        "source_sha256": identity.source_sha256,
        "identity_status": identity.identity_status,
    }


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
        except (SharedLineReplacementError, UnsupportedSourceError) as exc:
            report = _status("UNSUPPORTED_SOURCE", rule_id=rule_id, error=str(exc))
            return report
        except (SnapshotError, OSError) as exc:
            report = _status("INPUT_ERROR", rule_id=rule_id, error=str(exc))
            return report

        try:
            captured = _copy_and_fingerprint_policy(Path(policy_dir) if policy_dir else _DEFAULT_POLICY_DIR, capture_root)
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
                    "engine": {"name": captured.fingerprint.engine_name, "version": captured.fingerprint.engine_version},
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
