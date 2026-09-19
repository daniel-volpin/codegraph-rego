from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from codegraph.ingestion.snapshots import MethodIdentity, SnapshotError


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
        "syntactic_signature": identity.syntactic_signature,
        "source_key": identity.source_key,
        "declaration_key": identity.declaration_key,
        "canonical_key": identity.canonical_key,
        "source_sha256": identity.source_sha256,
        "identity_status": identity.identity_status,
        "resolution_status": identity.resolution_status,
        "resolved_descriptor": identity.resolved_descriptor,
        "resolved_binding_key": identity.resolved_binding_key,
    }
