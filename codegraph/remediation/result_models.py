from __future__ import annotations

from typing import Any, TypedDict


class CompilationResult(TypedDict, total=False):
    attempted: bool
    success: bool
    output_snippet: str | None
    skipped_reason: str | None


class ApplyMetadata(TypedDict):
    violation_id: str
    rule_id: str | None
    method_key: str | None
    target_method: str
    file_path: str
    attempt_count: int
    mode: str


class _ApplyFixResultRequired(TypedDict):
    status: str
    violation_id: str


class ApplyFixResult(_ApplyFixResultRequired, total=False):
    error: str | None
    rule_id: str | None
    method_key: str | None
    target_method: str | None
    file_path: str | None
    updated_source_code: str | None
    diff: str | None
    verification: dict[str, Any]
    compilation: CompilationResult
    metadata: ApplyMetadata
    generation: dict[str, Any] | None
    confidence: dict[str, Any]
    attempt_count: int
    llm_output: Any
    errors: list[str]
    raw_capture_files: list[str]
    predicate_trace: dict[str, Any] | None


def early_error_result(
    status: str,
    *,
    violation_id: str,
    error: str,
    rule_id: Any = None,
    method_key: str | None = None,
    target_method: str | None = None,
    file_path: str | None = None,
) -> ApplyFixResult:
    result: ApplyFixResult = {
        "status": status,
        "violation_id": violation_id,
        "error": error,
    }
    if rule_id is not None:
        result["rule_id"] = rule_id
    if method_key is not None:
        result["method_key"] = method_key
    if target_method is not None:
        result["target_method"] = target_method
    if file_path is not None:
        result["file_path"] = file_path
    return result


def generation_error_result(
    status: str,
    *,
    violation_id: str,
    error: str,
    target_method: str,
    file_path: str,
    rule_id: Any,
    method_key: str | None = None,
    attempt_count: int,
    llm_output: Any,
    errors: list[str],
    raw_capture_files: list[str],
    generation: dict[str, Any] | None,
    confidence: dict[str, Any],
) -> ApplyFixResult:
    return {
        "status": status,
        "error": error,
        "violation_id": violation_id,
        "target_method": target_method,
        "file_path": file_path,
        "rule_id": rule_id,
        "method_key": method_key,
        "attempt_count": attempt_count,
        "llm_output": llm_output,
        "errors": errors,
        "raw_capture_files": raw_capture_files,
        "generation": generation,
        "confidence": confidence,
    }


def apply_result(
    status: str,
    *,
    violation_id: str,
    rule_id: Any,
    method_key: str | None,
    target_method: str,
    file_path: str,
    updated_source_code: str,
    diff: str,
    verification: dict[str, Any],
    compilation: CompilationResult,
    metadata: ApplyMetadata,
    generation: dict[str, Any] | None,
    confidence: dict[str, Any],
    error: str | None,
    predicate_trace: dict[str, Any] | None = None,
) -> ApplyFixResult:
    """Full apply-flow result (OK, BUILD_ERROR, or final VERIFICATION_ERROR)."""
    result: ApplyFixResult = {
        "status": status,
        "violation_id": violation_id,
        "rule_id": rule_id,
        "method_key": method_key,
        "target_method": target_method,
        "file_path": file_path,
        "updated_source_code": updated_source_code,
        "diff": diff,
        "verification": verification,
        "compilation": compilation,
        "metadata": metadata,
        "generation": generation,
        "confidence": confidence,
        "error": error,
    }
    if predicate_trace is not None:
        result["predicate_trace"] = predicate_trace
    return result


def build_generation_payload(
    *,
    decision: str | None,
    edits: list[dict[str, Any]] | None,
    replacement_method_lines: list[str] | None,
    replacement_method_code: str | None,
    reason: str | None,
    raw_response_valid: bool,
    schema_error: str | None,
) -> dict[str, Any]:
    return {
        "decision": decision,
        "edits": edits,
        "replacement_method_lines": replacement_method_lines,
        "replacement_method_code": replacement_method_code,
        "reason": reason,
        "raw_response_valid": raw_response_valid,
        "schema_error": schema_error,
    }


def build_no_fix_response(
    *,
    violation_id: str,
    context: dict[str, Any],
    reason: str,
    attempt_count: int | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "status": "NO_FIX",
        "error": f"NO_FIX: {reason}",
        "violation_id": violation_id,
        "method_key": context.get("method_key"),
        "target_method": context.get("target_method"),
        "file_path": context.get("file_path"),
        "rule_id": context.get("rule_id"),
        "generation": {
            "decision": "no_fix",
            "edits": [],
            "replacement_method_lines": None,
            "replacement_method_code": None,
            "reason": reason,
            "raw_response_valid": True,
            "schema_error": None,
        },
    }
    if attempt_count is not None:
        payload["attempt_count"] = attempt_count
    return payload
