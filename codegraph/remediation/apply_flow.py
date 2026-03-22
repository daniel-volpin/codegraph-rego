from __future__ import annotations

import difflib
import logging
import tempfile
from pathlib import Path
from typing import Any

from codegraph.config import settings
from codegraph.ingestion.service import process_single_file_content
from codegraph.policy.integration import PolicyEvaluator
from codegraph.remediation.capabilities import get_remediation_capability
from codegraph.policy.trace import PolicyStateTrace, filter_predicate_trace, project_trace_profile
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
from codegraph.remediation.validation import extract_assistant_content
from codegraph.remediation.verification import build_verification_summary
from codegraph.telemetry import get_tracer

LOGGER = logging.getLogger(__name__)
_tracer = get_tracer("codegraph.remediation.apply_flow")


def _unified_diff(before: str, after: str, *, label: str = "method") -> str:
    diff = difflib.unified_diff(
        before.splitlines(),
        after.splitlines(),
        fromfile=f"{label} (before)",
        tofile=f"{label} (after)",
        lineterm="",
    )
    return "\n".join(diff)


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
        return early_error_result(
            "INVALID",
            violation_id=violation_id,
            error=capability.reason_code,
            rule_id=rule_id,
            target_method=context.get("target_method") or target_method,
            file_path=context.get("file_path") or file_path,
        )

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
        return response

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

    original_content = resolved_path.read_text(encoding="utf-8")
    baseline_violations = context.get("baseline_violations") or []
    attempt_errors: list[str] = []
    updated_content = None
    original_method = None
    updated_method = None
    raw_output = None
    raw_capture_files: list[str] = []
    generation_payload: dict[str, Any] | None = None
    confidence: dict[str, Any] = {}
    before_trace_raw = None
    try:
        tmp_eval = PolicyEvaluator()
        before_trace_raw = tmp_eval.trace(target_method, source_path_override=resolved_path.as_posix())
        if before_trace_raw:
            prompt_context = dict(prompt_context) if prompt_context else {}
            _before_filtered = filter_predicate_trace(before_trace_raw)
            trace_profile = project_trace_profile(str(context.get("rule_id")), _before_filtered)
            if trace_profile is not None:
                prompt_context["normalized_trace_profile"] = trace_profile
    except Exception as exc:
        LOGGER.warning("Shadow trace failed on baseline: %s", exc)

    context["prompt_context"] = prompt_context

    for attempt in range(max_attempts):
        with _tracer.start_as_current_span("remediation.attempt") as attempt_span:
            attempt_span.set_attribute("attempt_num", attempt + 1)
            llm_output = service.propose_method_edits(context, previous_errors=attempt_errors)
            updated_source = llm_output.get("replacement_method_code")
            updated_source_lines = llm_output.get("replacement_method_lines")
            raw_output = llm_output.get("raw_output")
            generation_payload = llm_output.get("generation")
            attempt_span.set_attribute("schema_valid", bool((generation_payload or {}).get("raw_response_valid")))
            attempt_span.set_attribute("decision", str(llm_output.get("decision") or ""))
            attempt_span.set_attribute("edits_count", len(llm_output.get("edits") or []))
            if not updated_source:
                if llm_output.get("decision") == "no_fix":
                    reason = llm_output.get("reason") or "no safe minimal fix available"
                    result = service._build_no_fix_response(
                        violation_id=violation_id,
                        context=context,
                        reason=reason,
                        attempt_count=attempt + 1,
                    )
                    result["confidence"] = service._build_confidence(
                        context=context,
                        support_tier=capability.support_tier,
                        decision="no_fix",
                        structured_valid=bool((llm_output.get("generation") or {}).get("raw_response_valid")),
                        attempt_count=attempt + 1,
                    )
                    result["errors"] = attempt_errors
                    attempt_span.set_attribute("outcome", "no_fix")
                    return result
                schema_error = llm_output.get("schema_error")
                if schema_error:
                    attempt_errors.append(summarize_retry_error(str(schema_error)))
                    attempt_span.set_attribute("error_summary", str(schema_error)[:200])
                else:
                    attempt_errors.append("empty_edits")
                    attempt_span.set_attribute("error_summary", "empty_edits")
                if settings.remediation_raw_capture_enabled and raw_output:
                    capture_path = capture_raw_llm_output(
                        raw_capture_dir,
                        extract_testcase_id(target_method),
                        attempt + 1,
                        extract_assistant_content(raw_output),
                    )
                    if capture_path:
                        raw_capture_files.append(capture_path)
                attempt_span.set_attribute("outcome", "retry")
                continue

            confidence = service._build_confidence(
                context=context,
                support_tier=capability.support_tier,
                decision=str(llm_output.get("decision") or ""),
                structured_valid=bool((generation_payload or {}).get("raw_response_valid")),
                attempt_count=attempt + 1,
            )
            attempt_span.set_attribute("confidence_score", float(confidence.get("score") or -1.0))
            attempt_span.set_attribute("confidence_band", str(confidence.get("band") or ""))

            if mode == "apply" and settings.remediation_confidence_gate_enabled:
                if confidence.get("band") != "apply":
                    result = service._build_no_fix_response(
                        violation_id=violation_id,
                        context=context,
                        reason="confidence gate requires manual review before apply",
                        attempt_count=attempt + 1,
                    )
                    result["confidence"] = confidence
                    result["errors"] = attempt_errors
                    attempt_span.set_attribute("outcome", "confidence_gate_blocked")
                    return result

            try:
                updated_content, original_method, updated_method = service._replace_method_in_source(
                    original_content,
                    updated_source_lines or [],
                    target_method,
                )
                attempt_span.set_attribute("outcome", "replacement_ok")
                break
            except ValueError as exc:
                attempt_errors.append(summarize_retry_error(str(exc)))
                attempt_span.set_attribute("error_summary", str(exc)[:200])
                attempt_span.set_attribute("outcome", "replacement_error")
                continue

    if not updated_content or not updated_method or not original_method:
        final_status = "REPLACEMENT_ERROR"
        final_error = "Failed to produce a valid method replacement"
        if generation_payload and generation_payload.get("raw_response_valid") is False:
            final_status = "GENERATION_ERROR"
            final_error = generation_payload.get("schema_error") or final_error
        return generation_error_result(
            final_status,
            violation_id=violation_id,
            error=final_error,
            target_method=target_method,
            file_path=file_path,
            rule_id=context.get("rule_id"),
            attempt_count=min(max_attempts, len(attempt_errors)),
            llm_output=raw_output,
            errors=attempt_errors,
            raw_capture_files=raw_capture_files,
            generation=generation_payload,
            confidence=confidence,
        )

    diff = _unified_diff(original_method, updated_method, label=target_method)
    compilation: CompilationResult = {
        "attempted": False,
        "success": False,
        "output_snippet": None,
        "skipped_reason": "No build system detected",
    }
    verification: dict[str, Any] = {}
    apply_successful = False
    attempt_count = min(max_attempts, max(1, len(attempt_errors) + 1))
    live_workspace_modified = False
    graph_modified = False

    try:
        with tempfile.TemporaryDirectory() as tmp:
            _temp_root, temp_file_path, temp_build_root = service._prepare_temp_workspace(Path(tmp), resolved_path)
            temp_file_path.write_text(updated_content, encoding="utf-8")
            compilation = service._compile_project(temp_build_root, build_command=build_command)

            try:
                if mode == "apply":
                    live_workspace_modified = True
                    resolved_path.write_text(updated_content, encoding="utf-8")

                graph_modified = True
                process_single_file_content(file_path, updated_content)
            except Exception as exc:  # pragma: no cover - runtime guard
                if LOGGER.isEnabledFor(logging.DEBUG):
                    LOGGER.exception("Failed to re-ingest updated file: %s", exc)
                else:
                    LOGGER.error("Failed to re-ingest updated file: %s", exc)
                return partial_error_result(
                    violation_id=violation_id,
                    error=str(exc),
                    target_method=target_method,
                    file_path=file_path,
                    rule_id=context.get("rule_id"),
                    updated_source_code=updated_method,
                    diff=diff,
                    compilation=compilation,
                    generation=generation_payload,
                    confidence=confidence,
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

            can_apply = (
                mode == "apply"
                and verification.get("target_rule_status") == "PASS"
                and verification.get("overall_status") == "PASS"
                and (not compilation.get("attempted") or compilation.get("success"))
            )
            apply_successful = bool(can_apply)
    except Exception as exc:  # pragma: no cover - runtime guard
        if LOGGER.isEnabledFor(logging.DEBUG):
            LOGGER.exception("Apply remediation failed: %s", exc)
        else:
            LOGGER.error("Apply remediation failed: %s", exc)
        return partial_error_result(
            violation_id=violation_id,
            error=str(exc),
            target_method=target_method,
            file_path=file_path,
            rule_id=context.get("rule_id"),
            updated_source_code=updated_method,
            diff=diff,
            compilation=compilation,
            generation=generation_payload,
            confidence=confidence,
        )
    finally:
        if graph_modified and (mode != "apply" or not apply_successful):
            try:
                process_single_file_content(file_path, original_content)
            except Exception as exc:  # pragma: no cover - runtime guard
                LOGGER.warning("Failed to restore original graph content for %s: %s", file_path, exc)
        if live_workspace_modified and (mode != "apply" or not apply_successful):
            try:
                resolved_path.write_text(original_content, encoding="utf-8")
            except Exception as exc:  # pragma: no cover - filesystem guard
                LOGGER.warning("Failed to restore original content for %s: %s", resolved_path, exc)

    status = "OK"
    if verification.get("error"):
        status = "VERIFICATION_ERROR"
    elif compilation.get("attempted") and not compilation.get("success"):
        status = "BUILD_ERROR"
    elif verification.get("overall_status") == "FAIL" or verification.get("target_rule_status") == "FAIL":
        status = "VERIFICATION_ERROR"
    if mode == "apply" and not apply_successful:
        status = "VERIFICATION_ERROR"

    trace_rule_id = str(context.get("rule_id"))
    before_filtered = filter_predicate_trace(before_trace_raw)
    after_filtered = filter_predicate_trace(after_trace_raw)
    trace_obj = PolicyStateTrace(
        package_path="data.iso27001",
        rule_id=trace_rule_id,
        trace_source="package_root_eval",
        before_trace_raw=before_trace_raw,
        after_trace_raw=after_trace_raw,
        before_trace_filtered=before_filtered,
        after_trace_filtered=after_filtered,
        before_trace_normalized=project_trace_profile(trace_rule_id, before_filtered),
        after_trace_normalized=project_trace_profile(trace_rule_id, after_filtered),
        trace_fields_used=list(before_trace_raw.keys() if before_trace_raw else []),
    )

    metadata: ApplyMetadata = {
        "violation_id": violation_id,
        "rule_id": context.get("rule_id"),
        "target_method": target_method,
        "file_path": file_path,
        "attempt_count": attempt_count,
        "mode": mode,
    }
    return apply_result(
        status,
        violation_id=violation_id,
        rule_id=context.get("rule_id"),
        target_method=target_method,
        file_path=file_path,
        updated_source_code=updated_method,
        diff=diff,
        verification=verification,
        compilation=compilation,
        metadata=metadata,
        generation=generation_payload,
        confidence=confidence,
        error=None if status == "OK" else (verification.get("error") or "Apply verification failed"),
        predicate_trace=trace_obj.model_dump(),
    )
