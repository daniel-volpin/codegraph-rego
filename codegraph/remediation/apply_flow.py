from __future__ import annotations

import logging
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from codegraph.config import settings
from codegraph.ingestion.service import WorkspacePublication, ingest
from codegraph.ingestion.snapshots import (
    SnapshotError,
    StaleSourceError,
    create_source_snapshot_from_bytes,
)
from codegraph.policy.trace import PolicyStateTrace, filter_predicate_trace, project_trace_profile
from codegraph.remediation.candidate import InvalidCandidateError, build_candidate_overlay
from codegraph.remediation.capabilities import get_remediation_capability
from codegraph.remediation.editing import unified_diff
from codegraph.remediation.metrics import (
    capture_raw_llm_output,
    extract_testcase_id,
    summarize_retry_error,
)
from codegraph.remediation.result_models import (
    ApplyFixResult,
    ApplyMetadata,
    CompilationResult,
    apply_result,
    early_error_result,
    generation_error_result,
)
from codegraph.remediation.scoped_verification import verify_candidate
from codegraph.remediation.validation import extract_assistant_content
from codegraph.telemetry import get_tracer

LOGGER = logging.getLogger(__name__)
_tracer = get_tracer("codegraph.remediation.apply_flow")


@dataclass
class _ReplacementAttemptOutcome:
    updated_content: str | None = None
    candidate_file_bytes: bytes | None = None
    candidate_method_bytes: bytes | None = None
    original_method: str | None = None
    updated_method: str | None = None
    raw_output: Any = None
    raw_capture_files: list[str] = field(default_factory=list)
    generation_payload: dict[str, Any] | None = None
    confidence: dict[str, Any] = field(default_factory=dict)
    attempt_errors: list[str] = field(default_factory=list)
    terminal_result: ApplyFixResult | None = None


def _unified_diff(before: str, after: str, *, label: str = "method") -> str:
    return unified_diff(before, after, label=label)


def _build_passed(compilation: CompilationResult) -> bool:
    return bool(compilation.get("attempted")) and bool(compilation.get("success"))


def _verification_passed(verification: dict[str, Any]) -> bool:
    return verification.get("status") == "POLICY_PASS"


def _can_commit_apply(mode: str, verification: dict[str, Any], compilation: CompilationResult) -> bool:
    return mode == "apply" and _verification_passed(verification) and _build_passed(compilation)


def _final_status(
    *,
    mode: str,
    verification: dict[str, Any],
    compilation: CompilationResult,
    apply_successful: bool,
    restore_failed: bool,
) -> str:
    if restore_failed:
        return "VERIFICATION_ERROR"
    if verification.get("error"):
        return "VERIFICATION_ERROR"
    if not _build_passed(compilation):
        if compilation.get("attempted"):
            return "BUILD_ERROR"
        return "VERIFICATION_ERROR"
    if not _verification_passed(verification):
        return "VERIFICATION_ERROR"
    if mode == "apply" and not apply_successful:
        return "VERIFICATION_ERROR"
    return "OK"


def _final_error(status: str, verification: dict[str, Any], *, restore_failed: bool) -> str | None:
    if status == "OK":
        return None
    if restore_failed:
        primary_error = verification.get("error")
        rollback_error = "Rollback failed: workspace may be left in candidate state"
        return f"{primary_error}; {rollback_error}" if primary_error else rollback_error
    return verification.get("error") or "Apply verification failed"


def _restore_file(
    resolved_path: Path,
    original_bytes: bytes,
    expected_current_bytes: bytes | None,
) -> bool:
    try:
        if expected_current_bytes is not None and resolved_path.read_bytes() != expected_current_bytes:
            LOGGER.warning("Refusing to restore %s because it changed after remediation wrote the candidate.", resolved_path)
            return False
        resolved_path.write_bytes(original_bytes)
        return True
    except OSError as exc:  # pragma: no cover - filesystem guard
        LOGGER.warning("Failed to restore original content for %s: %s", resolved_path, exc)
        return False


def _should_restore(mode: str, apply_successful: bool) -> bool:
    return mode != "apply" or not apply_successful


def _method_key_relative_path(method_key: str) -> Path:
    try:
        _, tail = method_key.split(":", 1)
    except ValueError as exc:
        raise ValueError("invalid_method_key") from exc
    relative = tail.split("#file:", 1)[0] if "#file:" in tail else tail.split("#", 1)[0]
    if not relative:
        raise ValueError("invalid_method_key")
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("invalid_method_key")
    return path


def _workspace_root_for(resolved_path: Path, method_key: str) -> Path:
    relative = _method_key_relative_path(method_key)
    resolved = resolved_path.resolve()
    relative_parts = relative.parts
    if len(resolved.parts) >= len(relative_parts) and resolved.parts[-len(relative_parts) :] == relative_parts:
        root_parts = resolved.parts[: -len(relative_parts)]
        return Path(*root_parts) if root_parts else Path("/")
    raise ValueError("source_path_method_key_mismatch")


def _apply_work_root() -> Path:
    root = Path.cwd() / "build" / "remediation-apply-work"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _publish_workspace_revision(workspace_root: Path) -> WorkspacePublication:
    return ingest(workspace_root.as_posix(), progress_callback=None, source_roots=None)


def _required_evidence_source_sha256(context: dict[str, Any]) -> str:
    evidence = context.get("evidence") if isinstance(context.get("evidence"), dict) else {}
    value = evidence.get("source_sha256")
    if not isinstance(value, str) or not value:
        raise ValueError("evidence.source_sha256 is required")
    return value


def _stale_verification(rule_id: str) -> dict[str, Any]:
    return {
        "status": "STALE_CANDIDATE",
        "policy_status": "NOT_EVALUATED",
        "build_status": "NOT_EVALUATED",
        "target_rule_status": "UNKNOWN",
        "rule_id": rule_id,
        "stale_reasons": ["source_sha256_mismatch"],
        "error": "source changed during remediation",
    }


def _policy_state_trace(
    *,
    rule_id: str,
    before_trace_raw: dict[str, Any] | None,
    after_trace_raw: dict[str, Any] | None,
) -> dict[str, Any]:
    before_filtered = filter_predicate_trace(before_trace_raw)
    after_filtered = filter_predicate_trace(after_trace_raw)
    trace_obj = PolicyStateTrace(
        package_path="data.iso27001",
        rule_id=rule_id,
        trace_source="package_root_eval",
        before_trace_raw=before_trace_raw,
        after_trace_raw=after_trace_raw,
        before_trace_filtered=before_filtered,
        after_trace_filtered=after_filtered,
        before_trace_normalized=project_trace_profile(rule_id, before_filtered),
        after_trace_normalized=project_trace_profile(rule_id, after_filtered),
        trace_fields_used=list(before_trace_raw.keys() if before_trace_raw else []),
    )
    return trace_obj.model_dump()


def _capture_retry_raw_output(
    *,
    raw_capture_dir: str | None,
    target_method: str,
    raw_output: Any,
    attempt_num: int,
) -> str | None:
    if not settings.remediation_raw_capture_enabled or not raw_output:
        return None
    return capture_raw_llm_output(
        raw_capture_dir,
        extract_testcase_id(target_method),
        attempt_num,
        extract_assistant_content(raw_output),
    )


def _handle_missing_updated_source(
    *,
    service: Any,
    llm_output: dict[str, Any],
    outcome: _ReplacementAttemptOutcome,
    violation_id: str,
    context: dict[str, Any],
    capability: Any,
    target_method: str,
    raw_capture_dir: str | None,
    attempt_num: int,
    attempt_span: Any,
) -> ApplyFixResult | None:
    if llm_output.get("decision") == "no_fix":
        reason = llm_output.get("reason") or "no safe minimal fix available"
        result = service._build_no_fix_response(
            violation_id=violation_id,
            context=context,
            reason=reason,
            attempt_count=attempt_num,
        )
        result["confidence"] = service._build_confidence(
            context=context,
            support_tier=capability.support_tier,
            decision="no_fix",
            structured_valid=bool((llm_output.get("generation") or {}).get("raw_response_valid")),
            attempt_count=attempt_num,
        )
        result["errors"] = outcome.attempt_errors
        attempt_span.set_attribute("outcome", "no_fix")
        return result

    schema_error = llm_output.get("schema_error")
    error_summary = str(schema_error) if schema_error else "empty_edits"
    outcome.attempt_errors.append(summarize_retry_error(error_summary) if schema_error else "empty_edits")
    attempt_span.set_attribute("error_summary", error_summary[:200])

    capture_path = _capture_retry_raw_output(
        raw_capture_dir=raw_capture_dir,
        target_method=target_method,
        raw_output=outcome.raw_output,
        attempt_num=attempt_num,
    )
    if capture_path:
        outcome.raw_capture_files.append(capture_path)
    attempt_span.set_attribute("outcome", "retry")
    return None


def _confidence_gate_result(
    *,
    service: Any,
    violation_id: str,
    context: dict[str, Any],
    confidence: dict[str, Any],
    attempt_errors: list[str],
    attempt_num: int,
) -> ApplyFixResult:
    result = service._build_no_fix_response(
        violation_id=violation_id,
        context=context,
        reason="confidence gate requires manual review before apply",
        attempt_count=attempt_num,
    )
    result["confidence"] = confidence
    result["errors"] = attempt_errors
    return result


def _run_replacement_attempts(
    *,
    service: Any,
    context: dict[str, Any],
    capability: Any,
    violation_id: str,
    target_method: str,
    mode: str,
    max_attempts: int,
    raw_capture_dir: str | None,
    baseline_snapshot: Any,
) -> _ReplacementAttemptOutcome:
    outcome = _ReplacementAttemptOutcome()
    for attempt in range(max_attempts):
        attempt_num = attempt + 1
        with _tracer.start_as_current_span("remediation.attempt") as attempt_span:
            attempt_span.set_attribute("attempt_num", attempt_num)
            llm_output = service.propose_method_edits(context, previous_errors=outcome.attempt_errors)
            updated_source = llm_output.get("replacement_method_code")
            updated_source_lines = llm_output.get("replacement_method_lines")
            outcome.raw_output = llm_output.get("raw_output")
            outcome.generation_payload = llm_output.get("generation")
            attempt_span.set_attribute("schema_valid", bool((outcome.generation_payload or {}).get("raw_response_valid")))
            attempt_span.set_attribute("decision", str(llm_output.get("decision") or ""))
            attempt_span.set_attribute("edits_count", len(llm_output.get("edits") or []))

            if not updated_source:
                outcome.terminal_result = _handle_missing_updated_source(
                    service=service,
                    llm_output=llm_output,
                    outcome=outcome,
                    violation_id=violation_id,
                    context=context,
                    capability=capability,
                    target_method=target_method,
                    raw_capture_dir=raw_capture_dir,
                    attempt_num=attempt_num,
                    attempt_span=attempt_span,
                )
                if outcome.terminal_result is not None:
                    return outcome
                continue

            outcome.confidence = service._build_confidence(
                context=context,
                support_tier=capability.support_tier,
                decision=str(llm_output.get("decision") or ""),
                structured_valid=bool((outcome.generation_payload or {}).get("raw_response_valid")),
                attempt_count=attempt_num,
            )
            attempt_span.set_attribute("confidence_score", float(outcome.confidence.get("score") or -1.0))
            attempt_span.set_attribute("confidence_band", str(outcome.confidence.get("band") or ""))

            if mode == "apply" and settings.remediation_confidence_gate_enabled and outcome.confidence.get("band") != "apply":
                outcome.terminal_result = _confidence_gate_result(
                    service=service,
                    violation_id=violation_id,
                    context=context,
                    confidence=outcome.confidence,
                    attempt_errors=outcome.attempt_errors,
                    attempt_num=attempt_num,
                )
                attempt_span.set_attribute("outcome", "confidence_gate_blocked")
                return outcome

            try:
                candidate_method_source = updated_source or "\n".join(updated_source_lines or [])
                overlay = build_candidate_overlay(baseline_snapshot, candidate_method_source.encode("utf-8"))
                outcome.updated_content = overlay.candidate_file_source
                outcome.candidate_file_bytes = overlay.candidate_file_bytes
                outcome.candidate_method_bytes = overlay.candidate_method_bytes
                outcome.original_method = baseline_snapshot.method_source
                outcome.updated_method = overlay.candidate_method_source
                attempt_span.set_attribute("outcome", "replacement_ok")
                return outcome
            except (InvalidCandidateError, ValueError) as exc:
                outcome.attempt_errors.append(summarize_retry_error(str(exc)))
                attempt_span.set_attribute("error_summary", str(exc)[:200])
                attempt_span.set_attribute("outcome", "replacement_error")
    return outcome


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
        return early_error_result(
            "INVALID",
            violation_id=violation_id,
            error="method_key is required",
        )
    try:
        source_relative_path = _method_key_relative_path(method_key)
    except ValueError as exc:
        return early_error_result(
            "INVALID",
            violation_id=violation_id,
            error=str(exc),
            method_key=method_key,
            file_path=file_path,
        )
    context = service.get_violation_context(violation_id, method_key=method_key, file_path=file_path)
    if context is None:
        return early_error_result(
            "NOT_FOUND",
            violation_id=violation_id,
            error=f"Violation {violation_id} not found",
            method_key=method_key,
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
            violation_id=violation_id,
            context=context,
            reason=preflight_reason,
            attempt_count=0,
        )
        response["confidence"] = service._build_confidence(
            context=context,
            support_tier=capability.support_tier,
            decision="no_fix",
            structured_valid=True,
            attempt_count=1,
        )
        return response

    resolved_path = service._resolve_file_path(file_path)
    if resolved_path is None:
        return early_error_result(
            "VERIFICATION_ERROR",
            violation_id=violation_id,
            error=f"Could not resolve file path: {file_path}",
            rule_id=context.get("rule_id"),
            method_key=method_key,
            target_method=target_method,
            file_path=file_path,
        )

    try:
        workspace_root = _workspace_root_for(resolved_path, method_key)
    except ValueError as exc:
        return early_error_result(
            "INVALID",
            violation_id=violation_id,
            error=str(exc),
            rule_id=context.get("rule_id"),
            method_key=method_key,
            target_method=target_method,
            file_path=file_path,
        )
    try:
        expected_source_sha256 = _required_evidence_source_sha256(context)
    except ValueError as exc:
        return early_error_result(
            "VERIFICATION_ERROR",
            violation_id=violation_id,
            error=str(exc),
            rule_id=context.get("rule_id"),
            method_key=method_key,
            target_method=target_method,
            file_path=file_path,
        )
    original_bytes = resolved_path.read_bytes()
    try:
        baseline_snapshot = create_source_snapshot_from_bytes(
            workspace_root=workspace_root,
            source_path=resolved_path,
            source_bytes=original_bytes,
            method_selector=method_key,
            expected_source_sha256=expected_source_sha256,
        )
    except StaleSourceError:
        return early_error_result(
            "VERIFICATION_ERROR",
            violation_id=violation_id,
            error="stale_source_hash",
            rule_id=context.get("rule_id"),
            method_key=method_key,
            target_method=target_method,
            file_path=file_path,
        )
    except SnapshotError as exc:
        return early_error_result(
            "VERIFICATION_ERROR",
            violation_id=violation_id,
            error=str(exc),
            rule_id=context.get("rule_id"),
            method_key=method_key,
            target_method=target_method,
            file_path=file_path,
        )
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
    compilation: CompilationResult = {
        "attempted": False,
        "success": False,
        "output_snippet": None,
        "skipped_reason": "No build system detected",
    }
    verification: dict[str, Any] = {}
    apply_successful = False
    attempt_count = min(max_attempts, max(1, len(replacement.attempt_errors) + 1))
    live_workspace_modified = False
    restore_failed = False
    cleanup: dict[str, bool | None] = {"file_restored": None, "revision_published": None}
    before_trace_raw = None
    after_trace_raw = None

    try:
        tempdir = tempfile.TemporaryDirectory(prefix="candidate-", dir=_apply_work_root())
        tmp = Path(tempdir.__enter__())
        try:
            _temp_root, temp_file_path, temp_build_root = service._prepare_temp_workspace(tmp, resolved_path)
            temp_file_path.parent.mkdir(parents=True, exist_ok=True)
            temp_file_path.write_bytes(replacement.candidate_file_bytes)
            compilation = service._compile_project(temp_build_root, build_command=build_command)

            verification_workspace = tmp / "verification-workspace"
            verification_source = verification_workspace / source_relative_path
            verification_source.parent.mkdir(parents=True, exist_ok=True)
            verification_source.write_bytes(original_bytes)
            candidate_method_rel = Path(".candidate") / "candidate-method.java"
            candidate_method_path = verification_workspace / candidate_method_rel
            candidate_method_path.parent.mkdir(parents=True, exist_ok=True)
            candidate_method_path.write_bytes(replacement.candidate_method_bytes)
            verification = verify_candidate(
                workspace_root=verification_workspace,
                source=source_relative_path,
                method_selector=method_key,
                candidate=candidate_method_rel,
                rule_id=str(context.get("rule_id")),
                expected_source_sha256=expected_source_sha256,
                work_dir=tmp / "verify",
            )
        finally:
            tempdir.__exit__(None, None, None)

        if resolved_path.read_bytes() != original_bytes:
            verification = _stale_verification(str(context.get("rule_id")))

        apply_successful = _can_commit_apply(mode, verification, compilation)
        if apply_successful:
            live_workspace_modified = True
            resolved_path.write_bytes(replacement.candidate_file_bytes)
            _publish_workspace_revision(workspace_root)
            cleanup["revision_published"] = True
    except Exception as exc:  # pragma: no cover - runtime guard
        _err = {"err": str(exc), "err_type": type(exc).__name__, "violation_id": violation_id}
        if LOGGER.isEnabledFor(logging.DEBUG):
            LOGGER.exception("Apply remediation failed", extra=_err)
        else:
            LOGGER.error("Apply remediation failed", extra=_err)
        apply_successful = False
        verification = {**verification, "error": str(exc)}
    finally:
        if live_workspace_modified and _should_restore(mode, apply_successful):
            cleanup["file_restored"] = _restore_file(
                resolved_path,
                original_bytes,
                replacement.candidate_file_bytes,
            )
        restore_failed = any(restored is False for restored in cleanup.values())

    verification["cleanup"] = cleanup
    status = _final_status(
        mode=mode,
        verification=verification,
        compilation=compilation,
        apply_successful=apply_successful,
        restore_failed=restore_failed,
    )
    error_message = _final_error(status, verification, restore_failed=restore_failed)

    metadata: ApplyMetadata = {
        "violation_id": violation_id,
        "rule_id": context.get("rule_id"),
        "method_key": method_key,
        "target_method": target_method,
        "file_path": file_path,
        "attempt_count": attempt_count,
        "mode": mode,
    }
    return apply_result(
        status,
        violation_id=violation_id,
        rule_id=context.get("rule_id"),
        method_key=method_key,
        target_method=target_method,
        file_path=file_path,
        updated_source_code=replacement.updated_method,
        diff=diff,
        verification=verification,
        compilation=compilation,
        metadata=metadata,
        generation=replacement.generation_payload,
        confidence=replacement.confidence,
        error=error_message,
        predicate_trace=_policy_state_trace(
            rule_id=str(context.get("rule_id")),
            before_trace_raw=before_trace_raw,
            after_trace_raw=after_trace_raw,
        ),
    )
