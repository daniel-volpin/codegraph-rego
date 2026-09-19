from __future__ import annotations

import hashlib
import json
import logging
import subprocess
from pathlib import Path
from typing import Any

from codegraph.ingestion.snapshots import SourceSnapshot, sha256_hex
from codegraph.policy.runtime import opa as opa_runtime
from codegraph.policy.runtime.bundles import build_evidence_bundle_from_source
from codegraph.remediation.context import build_virtual_graph_context
from codegraph.remediation.scoped_verification_types import CapturedPolicyInputs, PolicyFingerprint

LOGGER = logging.getLogger(__name__)


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
