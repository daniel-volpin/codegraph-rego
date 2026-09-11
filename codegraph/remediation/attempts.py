"""LLM replacement retry loop and candidate overlay assembly for remediation."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from codegraph.config import settings
from codegraph.remediation.candidate import InvalidCandidateError, build_candidate_overlay
from codegraph.remediation.metrics import (
    capture_raw_llm_output,
    extract_testcase_id,
    summarize_retry_error,
)
from codegraph.remediation.result_models import ApplyFixResult
from codegraph.remediation.validation import extract_assistant_content
from codegraph.telemetry import get_tracer

LOGGER = logging.getLogger(__name__)
_tracer = get_tracer("codegraph.remediation.attempts")


@dataclass
class ReplacementAttemptOutcome:
    """Carries accumulated state across LLM method edit generation attempts."""

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


def capture_retry_raw_output(
    *,
    raw_capture_dir: str | None,
    target_method: str,
    raw_output: Any,
    attempt_num: int,
) -> str | None:
    """Capture raw LLM generation text to debug artifacts if enabled."""
    if not settings.remediation_raw_capture_enabled or not raw_output:
        return None
    return capture_raw_llm_output(
        raw_capture_dir,
        extract_testcase_id(target_method),
        attempt_num,
        extract_assistant_content(raw_output),
    )


def handle_missing_updated_source(
    *,
    service: Any,
    llm_output: dict[str, Any],
    outcome: ReplacementAttemptOutcome,
    violation_id: str,
    context: dict[str, Any],
    capability: Any,
    target_method: str,
    raw_capture_dir: str | None,
    attempt_num: int,
    attempt_span: Any,
) -> ApplyFixResult | None:
    """Handle cases where the LLM declined to produce code or failed schema validation."""
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

    capture_path = capture_retry_raw_output(
        raw_capture_dir=raw_capture_dir,
        target_method=target_method,
        raw_output=outcome.raw_output,
        attempt_num=attempt_num,
    )
    if capture_path:
        outcome.raw_capture_files.append(capture_path)
    attempt_span.set_attribute("outcome", "retry")
    return None


def confidence_gate_result(
    *,
    service: Any,
    violation_id: str,
    context: dict[str, Any],
    confidence: dict[str, Any],
    attempt_errors: list[str],
    attempt_num: int,
) -> ApplyFixResult:
    """Build a terminal response when confidence gating forbids auto-apply."""
    result = service._build_no_fix_response(
        violation_id=violation_id,
        context=context,
        reason="confidence gate requires manual review before apply",
        attempt_count=attempt_num,
    )
    result["confidence"] = confidence
    result["errors"] = attempt_errors
    return result


def run_replacement_attempts(
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
) -> ReplacementAttemptOutcome:
    """Execute the multi-attempt loop asking the LLM for edits and building candidate overlays."""
    outcome = ReplacementAttemptOutcome()
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
                outcome.terminal_result = handle_missing_updated_source(
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
                outcome.terminal_result = confidence_gate_result(
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
