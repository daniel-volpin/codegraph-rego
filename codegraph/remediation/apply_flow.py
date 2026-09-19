from __future__ import annotations

import logging
import tempfile
from pathlib import Path
from typing import Any

from codegraph.embedding.service import EmbeddingService
from codegraph.ingestion.service import WorkspacePublication, ingest, rollback_workspace_revision
from codegraph.remediation.apply_flow_finalize import finalize_apply_result as _finalize_apply_result
from codegraph.remediation.apply_flow_helpers import (
    _method_key_relative_path,
    _prepare_and_snapshot_source,
    _unified_diff,
    _workspace_root_for,
    compile_verify_and_apply_candidate,
)
from codegraph.remediation.attempts import (
    ReplacementAttemptOutcome,
    capture_retry_raw_output,
    confidence_gate_result,
    handle_missing_updated_source,
    run_replacement_attempts,
)
from codegraph.remediation.capabilities import get_remediation_capability
from codegraph.remediation.result_models import (
    ApplyFixResult,
    CompilationResult,
    early_error_result,
    generation_error_result,
)
from codegraph.remediation.scoped_verification import verify_candidate
from codegraph.telemetry import get_tracer

__all__ = [
    "execute_apply_fix",
    "ingest",
    "rollback_workspace_revision",
    "tempfile",
    "verify_candidate",
    "_build_search_embeddings",
    "_workspace_root_for",
]

LOGGER = logging.getLogger(__name__)
_tracer = get_tracer("codegraph.remediation.apply_flow")

_ReplacementAttemptOutcome = ReplacementAttemptOutcome
_capture_retry_raw_output = capture_retry_raw_output
_handle_missing_updated_source = handle_missing_updated_source
_confidence_gate_result = confidence_gate_result
_run_replacement_attempts = run_replacement_attempts


def _publish_workspace_revision(workspace_root: Path) -> WorkspacePublication:
    return ingest(workspace_root.as_posix(), progress_callback=None, source_roots=None)


def _build_search_embeddings() -> None:
    EmbeddingService.build_embeddings(progress_callback=None)


def execute_apply_fix(
    service: Any,
    violation_id: str,
    *,
    method_key: str,
    file_path: str | None,
    mode: str,
    max_attempts: int,
    raw_capture_dir: str | None,
    build_command: str | None,
    prompt_context: dict[str, Any] | None = None,
) -> ApplyFixResult:
    with _tracer.start_as_current_span("remediation.fix") as fix_span:
        fix_span.set_attribute("violation_id", str(violation_id or ""))
        fix_span.set_attribute("method_key", str(method_key or ""))
        fix_span.set_attribute("file_path", str(file_path or ""))
        fix_span.set_attribute("mode", str(mode or ""))
        fix_span.set_attribute("max_attempts", max_attempts)
        result = _execute_apply_fix_inner(
            service,
            violation_id,
            method_key=method_key,
            file_path=file_path,
            mode=mode,
            max_attempts=max_attempts,
            raw_capture_dir=raw_capture_dir,
            build_command=build_command,
            prompt_context=prompt_context,
            _fix_span=fix_span,
        )
        fix_span.set_attribute("final_status", str(result.get("status") or ""))
        fix_span.set_attribute("attempt_count", int(result.get("attempt_count") or 0))
        confidence = result.get("confidence") or {}
        fix_span.set_attribute("confidence_score", float(confidence.get("score") or -1.0))
        fix_span.set_attribute("confidence_band", str(confidence.get("band") or ""))
        fix_span.set_attribute("rule_id", str(result.get("rule_id") or ""))
        return result


def _execute_apply_fix_inner(
    service: Any,
    violation_id: str,
    *,
    method_key: str,
    file_path: str | None,
    mode: str,
    max_attempts: int,
    raw_capture_dir: str | None,
    build_command: str | None,
    prompt_context: dict[str, Any] | None = None,
    _fix_span: Any = None,
) -> ApplyFixResult:
    max_attempts = max(1, max_attempts)
    if not method_key:
        return early_error_result("INVALID", violation_id=violation_id, error="method_key is required")
    try:
        source_relative_path = _method_key_relative_path(method_key)
    except ValueError as exc:
        return early_error_result(
            "INVALID", violation_id=violation_id, error=str(exc), method_key=method_key, file_path=file_path
        )
    context = service.get_violation_context(violation_id, method_key=method_key, file_path=file_path)
    if context is None:
        return early_error_result(
            "NOT_FOUND", violation_id=violation_id, error=f"Violation {violation_id} not found", method_key=method_key
        )

    rule_id = context.get("rule_id")
    capability = get_remediation_capability(rule_id, supported_rule_ids=service._FIX_STRATEGIES.keys())
    if not capability.supported:
        return early_error_result(
            "INVALID",
            violation_id=violation_id,
            error=capability.reason_code,
            rule_id=rule_id,
            method_key=method_key,
            target_method=context.get("target_method") or method_key,
            file_path=context.get("file_path") or file_path,
        )

    target_method = str(context.get("target_method") or method_key)
    file_path = file_path or context.get("file_path")
    if not file_path:
        return early_error_result(
            "INVALID",
            violation_id=violation_id,
            error="file_path is required to apply remediation",
            rule_id=context.get("rule_id"),
            method_key=method_key,
            target_method=target_method,
            file_path=file_path,
        )

    preflight_reason = service._preflight_fixability_reason(context)
    if preflight_reason:
        response = service._build_no_fix_response(
            violation_id=violation_id, context=context, reason=preflight_reason, attempt_count=0
        )
        response["confidence"] = service._build_confidence(
            context=context,
            support_tier=capability.support_tier,
            decision="no_fix",
            structured_valid=True,
            attempt_count=1,
        )
        return response

    prep = _prepare_and_snapshot_source(service, file_path, method_key, context)
    if prep[0] == "error":
        _, err_status, err_msg = prep
        return early_error_result(
            err_status,
            violation_id=violation_id,
            error=err_msg,
            rule_id=context.get("rule_id"),
            method_key=method_key,
            target_method=target_method,
            file_path=file_path,
        )
    resolved_path, workspace_root, original_bytes, expected_source_sha256, baseline_snapshot = prep
    context["prompt_context"] = prompt_context

    replacement = _run_replacement_attempts(
        service=service,
        context=context,
        capability=capability,
        violation_id=violation_id,
        target_method=target_method,
        mode=mode,
        max_attempts=max_attempts,
        raw_capture_dir=raw_capture_dir,
        baseline_snapshot=baseline_snapshot,
    )
    if replacement.terminal_result is not None:
        return replacement.terminal_result

    if (
        not replacement.updated_content
        or not replacement.updated_method
        or not replacement.original_method
        or replacement.candidate_file_bytes is None
        or replacement.candidate_method_bytes is None
    ):
        final_status = "REPLACEMENT_ERROR"
        final_error = "Failed to produce a valid method replacement"
        if replacement.generation_payload and replacement.generation_payload.get("raw_response_valid") is False:
            final_status = "GENERATION_ERROR"
            final_error = replacement.generation_payload.get("schema_error") or final_error
        return generation_error_result(
            final_status,
            violation_id=violation_id,
            error=final_error,
            target_method=target_method,
            file_path=file_path,
            rule_id=context.get("rule_id"),
            method_key=method_key,
            attempt_count=min(max_attempts, len(replacement.attempt_errors)),
            llm_output=replacement.raw_output,
            errors=replacement.attempt_errors,
            raw_capture_files=replacement.raw_capture_files,
            generation=replacement.generation_payload,
            confidence=replacement.confidence,
        )

    diff = _unified_diff(replacement.original_method, replacement.updated_method, label=target_method)
    attempt_count = min(max_attempts, max(1, len(replacement.attempt_errors) + 1))
    compilation, verification, apply_successful, restore_failed = _compile_verify_and_apply(
        service=service,
        violation_id=violation_id,
        method_key=method_key,
        context=context,
        resolved_path=resolved_path,
        workspace_root=workspace_root,
        source_relative_path=source_relative_path,
        original_bytes=original_bytes,
        expected_source_sha256=expected_source_sha256,
        replacement=replacement,
        mode=mode,
        build_command=build_command,
    )

    return _finalize_apply_result(
        mode=mode,
        verification=verification,
        compilation=compilation,
        apply_successful=apply_successful,
        restore_failed=restore_failed,
        violation_id=violation_id,
        context=context,
        method_key=method_key,
        target_method=target_method,
        file_path=file_path,
        attempt_count=attempt_count,
        diff=diff,
        replacement=replacement,
    )


def _compile_verify_and_apply(
    *,
    service: Any,
    violation_id: str,
    method_key: str,
    context: dict[str, Any],
    resolved_path: Path,
    workspace_root: Path,
    source_relative_path: Path,
    original_bytes: bytes,
    expected_source_sha256: str,
    replacement: _ReplacementAttemptOutcome,
    mode: str,
    build_command: str | None,
) -> tuple[CompilationResult, dict[str, Any], bool, bool]:
    return compile_verify_and_apply_candidate(
        service=service,
        violation_id=violation_id,
        method_key=method_key,
        context=context,
        resolved_path=resolved_path,
        workspace_root=workspace_root,
        source_relative_path=source_relative_path,
        original_bytes=original_bytes,
        expected_source_sha256=expected_source_sha256,
        replacement=replacement,
        mode=mode,
        build_command=build_command,
        verify_candidate_fn=verify_candidate,
        ingest_fn=ingest,
        rollback_fn=rollback_workspace_revision,
        build_embeddings_fn=_build_search_embeddings,
        tempfile_mod=tempfile,
    )
