from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
import uuid
from collections.abc import Mapping
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

from codegraph.config import settings
from codegraph.remediation.capabilities import remediation_capability_dict
from codegraph.telemetry import get_tracer

from .contracts import PolicyBundle, serialize_policy_bundle

_tracer = get_tracer("codegraph.policy.opa")

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_THIS_DIR, os.pardir, os.pardir, os.pardir))
POLICY_DIR = os.path.join(_PROJECT_ROOT, "policy")
POLICY_QUERY = "data.iso27001.violations"


def _opa_timeout_seconds() -> float:
    return float(settings.opa_timeout_seconds)


def normalize_violation_payload(payload: Any, logger) -> dict[str, Any] | None:
    if isinstance(payload, dict):
        return payload
    if isinstance(payload, str):
        try:
            parsed = json.loads(payload)
        except json.JSONDecodeError:
            logger.warning("Skipping non-JSON violation payload: %s", payload)
            return None
        if isinstance(parsed, dict):
            return parsed
        logger.warning("Skipping violation payload (unexpected type): %s", payload)
        return None
    logger.warning("Skipping unexpected OPA violation payload: %r", payload)
    return None


def _generate_decision_id() -> str:
    return uuid.uuid4().hex


def _now_iso_utc() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


def build_violation_response(
    normalized: dict[str, Any],
    bundle: Mapping[str, Any],
    control_meta: dict[str, Any] | None,
    *,
    decision_id: str | None = None,
    evaluated_at: str | None = None,
) -> dict[str, Any]:
    violation_id = normalized.get("violation_id")
    # Masked policy input is not a substitute for captured source evidence.
    source_code_raw = bundle.get("source_code_raw") or ""
    start_line = bundle.get("start_line")
    end_line = bundle.get("end_line")
    method_key = bundle.get("method_key")
    evidence = {
        "source_code": source_code_raw,
        "source_sha256": bundle.get("parser", {}).get("source_sha256"),
        "graph_context": bundle.get("graph_context", {}),
        "vector_context": bundle.get("vector_context", []),
        "file_path": bundle.get("file_path"),
        "method_key": method_key,
        "target_method": bundle.get("target_method"),
        "start_line": start_line,
        "end_line": end_line,
        "analysis_flags": bundle.get("analysis_flags", {}),
        "helper_summaries": bundle.get("helper_summaries", {}),
    }
    return {
        "violation_id": violation_id,
        "decision_id": decision_id or _generate_decision_id(),
        "evaluated_at": evaluated_at or _now_iso_utc(),
        "method_key": method_key,
        "target_method": bundle.get("target_method"),
        "file_path": bundle.get("file_path"),
        "reason": normalized.get("reason"),
        "severity": normalized.get("severity") or "high",
        "control_metadata": control_meta,
        "remediation": remediation_capability_dict(str(violation_id) if violation_id else None),
        "code_snippet": source_code_raw,
        "snippet_available": bool(source_code_raw),
        "snippet_start_line": start_line,
        "snippet_end_line": end_line,
        "evidence": evidence,
    }


def _serialize_for_opa(bundle: PolicyBundle | Mapping[str, Any]) -> dict[str, Any]:
    # When the bundle is already a plain dict (produced by build_evidence_bundle),
    # use it directly to preserve extra fields such as ``taint_paths`` that are
    # appended after the PolicyBundle serialization step.
    if isinstance(bundle, PolicyBundle):
        return bundle.to_dict()
    if isinstance(bundle, dict):
        return bundle
    return serialize_policy_bundle(bundle)


def _opa_eval_command(input_path: str, query: str, *, policy_dir: str | None = None) -> list[str]:
    return [
        "opa",
        "eval",
        "-f",
        "json",
        "-d",
        policy_dir or POLICY_DIR,
        "-i",
        input_path,
        query,
    ]


def _write_opa_input(tmp_dir: str, serialized_bundle: Mapping[str, Any]) -> str:
    input_path = os.path.join(tmp_dir, "input.json")
    with open(input_path, "w", encoding="utf-8") as file:
        json.dump(serialized_bundle, file)
    return input_path


@contextmanager
def _opa_input_dir(work_dir: str | None = None):
    if work_dir is None:
        with tempfile.TemporaryDirectory() as tmp:
            yield tmp
        return
    os.makedirs(work_dir, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="opa-input-", dir=work_dir) as tmp:
        yield tmp


def _run_opa_eval(cmd: list[str], target_method: Any, *, package_root: bool = False) -> subprocess.CompletedProcess[str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=_opa_timeout_seconds())
    except subprocess.TimeoutExpired as exc:
        scope = "package evaluation" if package_root else "evaluation"
        raise RuntimeError(f"OPA {scope} timed out for {target_method}") from exc

    if proc.returncode == 0:
        return proc

    scope = "package evaluation" if package_root else "evaluation"
    raise RuntimeError(f"OPA {scope} failed for {target_method}: {proc.stderr}")


def _parse_opa_stdout(stdout: str, *, package_root: bool = False) -> dict[str, Any]:
    try:
        parsed = json.loads(stdout)
    except json.JSONDecodeError as exc:
        scope = "OPA package output" if package_root else "OPA output"
        raise RuntimeError(f"Failed to parse {scope}") from exc
    if not isinstance(parsed, dict) or parsed.get("errors"):
        raise RuntimeError("Invalid OPA response envelope")
    return parsed


def _extract_opa_value(parsed: Mapping[str, Any], expected_type: type[list] | type[dict]) -> Any:
    result = parsed.get("result")
    if not isinstance(result, list) or len(result) != 1 or not isinstance(result[0], dict):
        raise RuntimeError("OPA query is undefined or returned an invalid result")
    expressions = result[0].get("expressions")
    if not isinstance(expressions, list) or len(expressions) != 1 or not isinstance(expressions[0], dict):
        raise RuntimeError("Invalid OPA result expressions")
    value = expressions[0].get("value")
    if not isinstance(value, expected_type):
        raise RuntimeError(f"OPA query did not return a {expected_type.__name__}")
    return value


def evaluate_bundle(
    bundle: PolicyBundle | Mapping[str, Any],
    *,
    policy_dir: str | None = None,
    work_dir: str | None = None,
) -> list[dict[str, Any]]:
    serialized_bundle = _serialize_for_opa(bundle)

    with _tracer.start_as_current_span("policy.evaluate") as span:
        span.set_attribute("target_method", str(serialized_bundle.get("target_method") or ""))
        span.set_attribute("bundle_size_bytes", len(json.dumps(serialized_bundle).encode()))
        t0 = time.monotonic()
        with _opa_input_dir(work_dir) as tmp:
            input_path = _write_opa_input(tmp, serialized_bundle)
            cmd = _opa_eval_command(input_path, POLICY_QUERY, policy_dir=policy_dir)
            try:
                proc = _run_opa_eval(cmd, serialized_bundle.get("target_method"))
                out = _parse_opa_stdout(proc.stdout)
            except RuntimeError as exc:
                span.set_attribute("opa_error", str(exc)[:200])
                raise
            finally:
                span.set_attribute("opa_duration_ms", round((time.monotonic() - t0) * 1000))
            span.set_attribute("opa_returncode", proc.returncode)
            violations = _extract_opa_value(out, list)
            if any(
                not isinstance(violation, dict) or not isinstance(violation.get("violation_id"), str)
                for violation in violations
            ):
                raise RuntimeError("OPA returned an invalid violation")
            span.set_attribute("violation_count", len(violations))
            return violations


def evaluate_package_root(
    bundle: PolicyBundle | Mapping[str, Any],
    package: str = "data.iso27001",
    *,
    policy_dir: str | None = None,
    work_dir: str | None = None,
) -> dict[str, Any]:
    serialized_bundle = _serialize_for_opa(bundle)
    with _opa_input_dir(work_dir) as tmp:
        input_path = _write_opa_input(tmp, serialized_bundle)
        cmd = _opa_eval_command(input_path, package, policy_dir=policy_dir)
        proc = _run_opa_eval(cmd, serialized_bundle.get("target_method"), package_root=True)
        out = _parse_opa_stdout(proc.stdout, package_root=True)
        return _extract_opa_value(out, dict)
