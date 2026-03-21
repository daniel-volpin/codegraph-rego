from __future__ import annotations

import json
import os
import subprocess
import tempfile
from typing import Any, Dict, List, Mapping, Optional

from codegraph.remediation.capabilities import remediation_capability_dict

from .contracts import PolicyBundle, serialize_policy_bundle

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.abspath(os.path.join(_THIS_DIR, os.pardir, os.pardir, os.pardir))
POLICY_DIR = os.path.join(_PROJECT_ROOT, "policy")
POLICY_QUERY = "data.iso27001.violations"


def normalize_violation_payload(payload: Any, logger) -> Optional[Dict[str, Any]]:
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


def build_violation_response(
    normalized: Dict[str, Any],
    bundle: Mapping[str, Any],
    control_meta: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    violation_id = normalized.get("violation_id") or normalized.get("id")
    source_code = bundle.get("source_code", "") or ""
    start_line = bundle.get("start_line")
    end_line = bundle.get("end_line")
    evidence = {
        "source_code": source_code,
        "graph_context": bundle.get("graph_context", {}),
        "vector_context": bundle.get("vector_context", []),
        "file_path": bundle.get("file_path"),
        "target_method": bundle.get("target_method"),
        "start_line": start_line,
        "end_line": end_line,
        "analysis_flags": bundle.get("analysis_flags", {}),
        "helper_summaries": bundle.get("helper_summaries", {}),
    }
    return {
        "violation_id": violation_id,
        "target_method": bundle.get("target_method"),
        "file_path": bundle.get("file_path"),
        "reason": normalized.get("reason"),
        "severity": normalized.get("severity") or "high",
        "control_metadata": control_meta,
        "remediation": remediation_capability_dict(str(violation_id) if violation_id else None),
        "code_snippet": source_code,
        "snippet_available": bool(source_code),
        "snippet_start_line": start_line,
        "snippet_end_line": end_line,
        "evidence": evidence,
    }


def evaluate_bundle(bundle: PolicyBundle | Mapping[str, Any]) -> List[Dict[str, Any]]:
    # When the bundle is already a plain dict (produced by build_evidence_bundle),
    # use it directly to preserve extra fields such as ``taint_paths`` that are
    # appended after the PolicyBundle serialization step.
    if isinstance(bundle, PolicyBundle):
        serialized_bundle = bundle.to_dict()
    elif isinstance(bundle, dict):
        serialized_bundle = bundle
    else:
        serialized_bundle = serialize_policy_bundle(bundle)
    with tempfile.TemporaryDirectory() as tmp:
        input_path = os.path.join(tmp, "input.json")
        with open(input_path, "w", encoding="utf-8") as file:
            json.dump(serialized_bundle, file)
        cmd = [
            "opa",
            "eval",
            "-f",
            "json",
            "-d",
            POLICY_DIR,
            "-i",
            input_path,
            POLICY_QUERY,
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError(f"OPA evaluation failed for {serialized_bundle.get('target_method')}: {proc.stderr}")
        try:
            out = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("Failed to parse OPA output") from exc
        result = out.get("result") or []
        if not result:
            return []
        expressions = result[0].get("expressions") or []
        if not expressions:
            return []
        return expressions[0].get("value") or []


def evaluate_package_root(bundle: PolicyBundle | Mapping[str, Any], package: str = "data.iso27001") -> Dict[str, Any]:
    if isinstance(bundle, PolicyBundle):
        serialized_bundle = bundle.to_dict()
    elif isinstance(bundle, dict):
        serialized_bundle = bundle
    else:
        serialized_bundle = serialize_policy_bundle(bundle)
    with tempfile.TemporaryDirectory() as tmp:
        input_path = os.path.join(tmp, "input.json")
        with open(input_path, "w", encoding="utf-8") as file:
            json.dump(serialized_bundle, file)
        cmd = [
            "opa",
            "eval",
            "-f",
            "json",
            "-d",
            POLICY_DIR,
            "-i",
            input_path,
            package,
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError(f"OPA package evaluation failed for {serialized_bundle.get('target_method')}: {proc.stderr}")
        try:
            out = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError("Failed to parse OPA package output") from exc
        result = out.get("result") or []
        if not result:
            return {}
        expressions = result[0].get("expressions") or []
        if not expressions:
            return {}
        return expressions[0].get("value") or {}
