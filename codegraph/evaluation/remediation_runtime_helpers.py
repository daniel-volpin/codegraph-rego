from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from codegraph.evaluation.benchmark import extract_testcase_id
from codegraph.evaluation.calibration import _safe_float

TRACKED_FINAL_STATUSES: Sequence[str] = (
    "OK",
    "NO_FIX",
    "GENERATION_ERROR",
    "REPLACEMENT_ERROR",
    "BUILD_ERROR",
    "VERIFICATION_ERROR",
)


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _safe_slug(value: str | None) -> str:
    normalized = re.sub(r"[^A-Za-z0-9_.-]+", "-", (value or "").strip())
    normalized = normalized.strip("-._")
    return normalized or "unknown"


def build_case_id(violation: Mapping[str, Any]) -> str:
    violation_id = str(violation.get("violation_id") or "unknown")
    target_method = str(violation.get("target_method") or "")
    file_path = str((violation.get("evidence") or {}).get("file_path") or violation.get("file_path") or "")
    testcase_id = extract_testcase_id(target_method or file_path) or "unknown"
    identity = "|".join((violation_id, target_method, file_path))
    digest = hashlib.sha1(identity.encode("utf-8")).hexdigest()[:10]
    return f"{_safe_slug(testcase_id)}_{_safe_slug(violation_id)}_{digest}"


def tracked_status_counts(results: Iterable[Mapping[str, Any]]) -> dict[str, int]:
    counts = {status: 0 for status in TRACKED_FINAL_STATUSES}
    for item in results:
        status = str(item.get("status") or "")
        if status in counts:
            counts[status] += 1
    return counts


def untracked_status_counts(results: Iterable[Mapping[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in results:
        status = str(item.get("status") or "")
        if not status or status in TRACKED_FINAL_STATUSES:
            continue
        counts[status] = counts.get(status, 0) + 1
    return counts


def build_stage_counts(results: Iterable[Mapping[str, Any]]) -> dict[str, int]:
    items = list(results)
    return {
        "attempted": len(items),
        "structured_valid": sum(1 for item in items if item.get("structured_valid") is True),
        "replacement_applied": sum(1 for item in items if item.get("replacement_applied") is True),
        "build_attempted": sum(1 for item in items if item.get("build_attempted") is True),
        "build_success": sum(1 for item in items if item.get("build_success") is True),
        "policy_fixed": sum(1 for item in items if item.get("policy_fixed") is True),
    }


def build_remediation_result(
    *,
    violation: Mapping[str, Any],
    apply_result: Mapping[str, Any],
    case_id: str,
) -> dict[str, Any]:
    verification = apply_result.get("verification") or {}
    compilation = apply_result.get("compilation") or {}
    generation = apply_result.get("generation")
    build_pass = compilation.get("success") if compilation.get("attempted") else None
    policy_fixed = apply_result.get("status") == "OK" and verification.get("target_rule_status") == "PASS"
    replacement_applied = bool(apply_result.get("updated_source_code"))
    structured_valid = isinstance(generation, dict) and generation.get("raw_response_valid") is True

    confidence = apply_result.get("confidence") or None
    confidence_score = _safe_float((confidence or {}).get("score")) if confidence else None
    confidence_band = (confidence or {}).get("band") if confidence else None
    fully_verified = policy_fixed and build_pass is True
    evidence = violation.get("evidence") or {}
    return {
        "case_id": case_id,
        "artifact_dir": f"cases/{case_id}",
        "violation_id": violation.get("violation_id"),
        "target_method": violation.get("target_method"),
        "file_path": evidence.get("file_path") or violation.get("file_path"),
        "status": apply_result.get("status"),
        "error": apply_result.get("error"),
        "patch_applied": replacement_applied,
        "policy_pass": policy_fixed,
        "build_pass": build_pass,
        "category": violation.get("category"),
        "verification": verification,
        "compilation": compilation,
        "diff": apply_result.get("diff"),
        "generation": generation,
        "errors": apply_result.get("errors"),
        "attempt_count": apply_result.get("attempt_count"),
        "raw_capture_files": apply_result.get("raw_capture_files"),
        "structured_valid": structured_valid,
        "replacement_applied": replacement_applied,
        "build_attempted": compilation.get("attempted") is True,
        "build_success": build_pass is True,
        "policy_fixed": policy_fixed,
        "fully_verified": fully_verified,
        "confidence": confidence,
        "confidence_score": confidence_score,
        "confidence_band": confidence_band,
    }


def build_agentic_remediation_result(
    *,
    violation: Mapping[str, Any],
    apply_result: Mapping[str, Any],
    case_id: str,
    ground_truth_label: bool,
) -> dict[str, Any]:
    verification = apply_result.get("verification") or {}
    status = apply_result.get("status")
    build_pass = verification.get("compile_passed")
    policy_fixed = status == "SUCCESS" and bool(verification.get("policy_passed"))
    replacement_applied = bool(apply_result.get("modified_files"))
    outcome_correct = (ground_truth_label and status == "SUCCESS") or (not ground_truth_label and status == "REFUSED")
    evidence = violation.get("evidence") or {}
    return {
        "case_id": case_id,
        "artifact_dir": f"cases/{case_id}",
        "violation_id": violation.get("violation_id"),
        "target_method": violation.get("target_method"),
        "file_path": evidence.get("file_path") or violation.get("file_path"),
        "status": status,
        "error": apply_result.get("reason") if status in {"ERROR", "MAX_TURNS_EXCEEDED"} else None,
        "patch_applied": replacement_applied,
        "policy_pass": policy_fixed,
        "build_pass": build_pass,
        "category": violation.get("category"),
        "ground_truth_label": ground_truth_label,
        "verification": verification,
        "compilation": {"attempted": build_pass is not None, "success": build_pass},
        "diff": apply_result.get("diff"),
        "reason": apply_result.get("reason"),
        "iterations": apply_result.get("iterations"),
        "errors": None,
        "attempt_count": apply_result.get("iterations"),
        "raw_capture_files": [],
        "structured_valid": False,
        "replacement_applied": replacement_applied,
        "build_attempted": build_pass is not None,
        "build_success": build_pass is True,
        "policy_fixed": policy_fixed,
        "fully_verified": policy_fixed and build_pass is True,
        "outcome_correct": outcome_correct,
        "confidence": None,
        "confidence_score": None,
        "confidence_band": None,
    }


def build_agentic_outcome_summary(results: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    items = list(results)
    correct_fix = correct_abstain = missed_fix = false_fix = inconclusive = 0
    for item in items:
        label = item.get("ground_truth_label")
        status = item.get("status")
        if label is True:
            if status == "SUCCESS":
                correct_fix += 1
            elif status == "REFUSED":
                missed_fix += 1
            else:
                inconclusive += 1
        elif label is False:
            if status == "REFUSED":
                correct_abstain += 1
            elif status == "SUCCESS":
                false_fix += 1
            else:
                inconclusive += 1
        else:
            inconclusive += 1
    total = len(items)
    correct = correct_fix + correct_abstain
    return {
        "total": total,
        "correct_fix": correct_fix,
        "correct_abstain": correct_abstain,
        "missed_fix": missed_fix,
        "false_fix": false_fix,
        "inconclusive_error_or_timeout": inconclusive,
        "correct_outcome_rate": round(correct / total, 4) if total else 0.0,
    }


def build_skipped_result(
    *,
    violation: Mapping[str, Any],
    case_id: str,
    error: str,
) -> dict[str, Any]:
    evidence = violation.get("evidence") or {}
    return {
        "case_id": case_id,
        "artifact_dir": f"cases/{case_id}",
        "violation_id": violation.get("violation_id"),
        "target_method": violation.get("target_method"),
        "file_path": evidence.get("file_path") or violation.get("file_path"),
        "status": "SKIPPED",
        "error": error,
        "patch_applied": False,
        "policy_pass": False,
        "build_pass": None,
        "category": violation.get("category"),
        "verification": {},
        "compilation": {},
        "diff": None,
        "generation": None,
        "errors": [error],
        "attempt_count": 0,
        "raw_capture_files": [],
        "structured_valid": False,
        "replacement_applied": False,
        "build_attempted": False,
        "build_success": False,
        "policy_fixed": False,
        "fully_verified": False,
        "confidence": None,
        "confidence_score": None,
        "confidence_band": None,
    }
