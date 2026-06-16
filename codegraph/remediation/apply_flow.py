from __future__ import annotations

import difflib
import logging
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from codegraph.config import settings
from codegraph.ingestion.service import process_single_file_content
from codegraph.policy.integration import PolicyEvaluator
from codegraph.policy.trace import PolicyStateTrace, filter_predicate_trace, project_trace_profile
from codegraph.remediation.capabilities import get_remediation_capability
from codegraph.remediation.editing import (
    read_source_preserving_format,
    write_source_preserving_format,
)
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
    partial_error_result,
)
from codegraph.remediation.shadow import maybe_attach_shadow_result
from codegraph.remediation.validation import extract_assistant_content
from codegraph.remediation.verification import build_verification_summary
from codegraph.telemetry import get_tracer

LOGGER = logging.getLogger(__name__)
_tracer = get_tracer("codegraph.remediation.apply_flow")


@dataclass
class _ReplacementAttemptOutcome:
    updated_content: str | None = None
    original_method: str | None = None
    updated_method: str | None = None
    raw_output: Any = None
    raw_capture_files: list[str] = field(default_factory=list)
    generation_payload: dict[str, Any] | None = None
    confidence: dict[str, Any] = field(default_factory=dict)
    attempt_errors: list[str] = field(default_factory=list)
    terminal_result: ApplyFixResult | None = None


def _unified_diff(before: str, after: str, *, label: str = "method") -> str:
    diff = difflib.unified_diff(
        before.splitlines(),
        after.splitlines(),
        fromfile=f"{label} (before)",
        tofile=f"{label} (after)",
        lineterm="",
    )
    return "\n".join(diff)


def _build_passed(compilation: CompilationResult) -> bool:
    return bool(compilation.get("attempted")) and bool(compilation.get("success"))


def _verification_passed(verification: dict[str, Any]) -> bool:
    return verification.get("target_rule_status") == "PASS" and verification.get("overall_status") == "PASS"


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
    if compilation.get("attempted") and not compilation.get("success"):
        return "BUILD_ERROR"
    if verification.get("overall_status") == "FAIL" or verification.get("target_rule_status") == "FAIL":
        return "VERIFICATION_ERROR"
    if mode == "apply" and not apply_successful:
        return "VERIFICATION_ERROR"
    return "OK"


def _final_error(status: str, verification: dict[str, Any], *, restore_failed: bool) -> str | None:
    if status == "OK":
        return None
    if restore_failed:
        return "Rollback failed: workspace/graph left in candidate state"
    return verification.get("error") or "Apply verification failed"


def _baseline_trace_context(
    *,
    target_method: str,
    resolved_path: Path,
    rule_id: Any,
    prompt_context: dict[str, Any] | None,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    try:
        before_trace_raw = PolicyEvaluator().trace(target_method, source_path_override=resolved_path.as_posix())
    except Exception as exc:
        LOGGER.warning("Shadow trace failed on baseline: %s", exc)
        return None, prompt_context

    if not before_trace_raw:
        return before_trace_raw, prompt_context

    enriched_context = dict(prompt_context) if prompt_context else {}
    before_filtered = filter_predicate_trace(before_trace_raw)
    trace_profile = project_trace_profile(str(rule_id), before_filtered)
    if trace_profile is not None:
        enriched_context["normalized_trace_profile"] = trace_profile
    return before_trace_raw, enriched_context


def _restore_graph(file_path: str, original_content: str) -> bool:
    try:
        process_single_file_content(file_path, original_content)
        return True
    except Exception as exc:  # pragma: no cover - runtime guard
        LOGGER.warning("Failed to restore original graph content for %s: %s", file_path, exc)
        return False


def _restore_file(
    resolved_path: Path,
    original_content: str,
    source_encoding: str,
    source_newline: str,
) -> bool:
    try:
        write_source_preserving_format(resolved_path, original_content, source_encoding, source_newline)
        return True
    except Exception as exc:  # pragma: no cover - filesystem guard
        LOGGER.warning("Failed to restore original content for %s: %s", resolved_path, exc)
        return False


def _should_restore(mode: str, apply_successful: bool) -> bool:
    return mode != "apply" or not apply_successful


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
    original_content: str,
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
                outcome.updated_content, outcome.original_method, outcome.updated_method = service._replace_method_in_source(
                    original_content,
                    updated_source_lines or [],
                    target_method,
                )
                attempt_span.set_attribute("outcome", "replacement_ok")
                return outcome
            except ValueError as exc:
                outcome.attempt_errors.append(summarize_retry_error(str(exc)))
                attempt_span.set_attribute("error_summary", str(exc)[:200])
                attempt_span.set_attribute("outcome", "replacement_error")
    return outcome


def execute_apply_fix(
    service: Any,
    violation_id: str,
    *,
    target_method: str | None,
    file_path: str | None,
    mode: str,
    max_attempts: int,
    raw_capture_dir: str | None,
    build_command: str | None,
    prompt_context: dict[str, Any] | None = None,
) -> ApplyFixResult:
    with _tracer.start_as_current_span("remediation.fix") as fix_span:
        fix_span.set_attribute("violation_id", str(violation_id or ""))
        fix_span.set_attribute("target_method", str(target_method or ""))
        fix_span.set_attribute("file_path", str(file_path or ""))
        fix_span.set_attribute("mode", str(mode or ""))
        fix_span.set_attribute("max_attempts", max_attempts)
        result = _execute_apply_fix_inner(
            service,
            violation_id,
            target_method=target_method,
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
    target_method: str | None,
    file_path: str | None,
    mode: str,
    max_attempts: int,
    raw_capture_dir: str | None,
    build_command: str | None,
    prompt_context: dict[str, Any] | None = None,
    _fix_span: Any = None,
) -> ApplyFixResult:
    max_attempts = max(1, max_attempts)
    context = service.get_violation_context(violation_id, target_method, file_path)
    if context is None:
        return early_error_result(
            "NOT_FOUND",
            violation_id=violation_id,
            error=f"Violation {violation_id} not found",
        )

    rule_id = context.get("rule_id")
    capability = get_remediation_capability(rule_id, supported_rule_ids=service._FIX_STRATEGIES.keys())
    if not capability.supported:
        result = early_error_result(
            "INVALID",
            violation_id=violation_id,
            error=capability.reason_code,
            rule_id=rule_id,
            target_method=context.get("target_method") or target_method,
            file_path=context.get("file_path") or file_path,
        )
        return maybe_attach_shadow_result(service, context=context, authoritative_result=result, build_command=build_command)

    target_method = target_method or context.get("target_method")
    file_path = file_path or context.get("file_path")
    if not target_method or not file_path:
        return early_error_result(
            "INVALID",
            violation_id=violation_id,
            error="target_method and file_path are required to apply remediation",
            rule_id=context.get("rule_id"),
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
        return maybe_attach_shadow_result(service, context=context, authoritative_result=response, build_command=build_command)

    resolved_path = service._resolve_file_path(file_path)
    if resolved_path is None:
        return early_error_result(
            "VERIFICATION_ERROR",
            violation_id=violation_id,
            error=f"Could not resolve file path: {file_path}",
            rule_id=context.get("rule_id"),
            target_method=target_method,
            file_path=file_path,
        )

    # Detect encoding + line ending up-front so the write-back path
    # preserves Windows-authored sources (CRLF) and BOM-prefixed files
    # rather than silently rewriting them to LF / no-BOM.
    original_content, source_encoding, source_newline = read_source_preserving_format(resolved_path)
    baseline_violations = context.get("baseline_violations") or []
    before_trace_raw, prompt_context = _baseline_trace_context(
        target_method=target_method,
        resolved_path=resolved_path,
        rule_id=context.get("rule_id"),
        prompt_context=prompt_context,
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
        original_content=original_content,
    )
    if replacement.terminal_result is not None:
        return replacement.terminal_result

    if not replacement.updated_content or not replacement.updated_method or not replacement.original_method:
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
    graph_modified = False
    restore_failed = False

    try:
        with tempfile.TemporaryDirectory() as tmp:
            _temp_root, temp_file_path, temp_build_root = service._prepare_temp_workspace(Path(tmp), resolved_path)
            write_source_preserving_format(temp_file_path, replacement.updated_content, source_encoding, source_newline)
            compilation = service._compile_project(temp_build_root, build_command=build_command)

            try:
                if mode == "apply":
                    live_workspace_modified = True
                    write_source_preserving_format(resolved_path, replacement.updated_content, source_encoding, source_newline)

                graph_modified = True
                process_single_file_content(file_path, replacement.updated_content)
            except Exception as exc:  # pragma: no cover - runtime guard
                _err = {"err": str(exc), "err_type": type(exc).__name__, "file_path": str(resolved_path)}
                if LOGGER.isEnabledFor(logging.DEBUG):
                    LOGGER.exception("Failed to re-ingest updated file", extra=_err)
                else:
                    LOGGER.error("Failed to re-ingest updated file", extra=_err)
                return partial_error_result(
                    violation_id=violation_id,
                    error=str(exc),
                    target_method=target_method,
                    file_path=file_path,
                    rule_id=context.get("rule_id"),
                    updated_source_code=replacement.updated_method,
                    diff=diff,
                    compilation=compilation,
                    generation=replacement.generation_payload,
                    confidence=replacement.confidence,
                )

            evaluator = PolicyEvaluator()
            after_eval = evaluator.evaluate(
                target_method,
                source_path_override=temp_file_path.as_posix() if mode == "dry_run" else None,
            )

            after_trace_raw = None
            try:
                after_trace_raw = evaluator.trace(
                    target_method,
                    source_path_override=temp_file_path.as_posix() if mode == "dry_run" else None,
                )
            except Exception as exc:
                LOGGER.warning("Shadow trace failed on candidate: %s", exc)
            if after_eval.get("error"):
                verification = {
                    "error": after_eval.get("error"),
                    "baseline": baseline_violations,
                    "after": after_eval.get("violations") or [],
                }
            else:
                verification = build_verification_summary(
                    context.get("rule_id"),
                    baseline_violations,
                    after_eval.get("violations") or [],
                )

            apply_successful = _can_commit_apply(mode, verification, compilation)
    except Exception as exc:  # pragma: no cover - runtime guard
        _err = {"err": str(exc), "err_type": type(exc).__name__, "violation_id": violation_id}
        if LOGGER.isEnabledFor(logging.DEBUG):
            LOGGER.exception("Apply remediation failed", extra=_err)
        else:
            LOGGER.error("Apply remediation failed", extra=_err)
        return partial_error_result(
            violation_id=violation_id,
            error=str(exc),
            target_method=target_method,
            file_path=file_path,
            rule_id=context.get("rule_id"),
            updated_source_code=replacement.updated_method,
            diff=diff,
            compilation=compilation,
            generation=replacement.generation_payload,
            confidence=replacement.confidence,
        )
    finally:
        if graph_modified and _should_restore(mode, apply_successful):
            restore_failed = restore_failed or not _restore_graph(file_path, original_content)
        if live_workspace_modified and _should_restore(mode, apply_successful):
            restore_failed = restore_failed or not _restore_file(
                resolved_path,
                original_content,
                source_encoding,
                source_newline,
            )

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
        "target_method": target_method,
        "file_path": file_path,
        "attempt_count": attempt_count,
        "mode": mode,
    }
    result = apply_result(
        status,
        violation_id=violation_id,
        rule_id=context.get("rule_id"),
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
    return maybe_attach_shadow_result(service, context=context, authoritative_result=result, build_command=build_command)
