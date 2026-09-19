from __future__ import annotations

from typing import Any

from codegraph.policy.trace import PolicyStateTrace, filter_predicate_trace, project_trace_profile
from codegraph.remediation.apply_flow_helpers import _final_error, _final_status
from codegraph.remediation.attempts import ReplacementAttemptOutcome
from codegraph.remediation.result_models import (
    ApplyFixResult,
    ApplyMetadata,
    CompilationResult,
    apply_result,
)


def policy_state_trace(
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


def finalize_apply_result(
    *,
    mode: str,
    verification: dict[str, Any],
    compilation: CompilationResult,
    apply_successful: bool,
    restore_failed: bool,
    violation_id: str,
    context: dict[str, Any],
    method_key: str,
    target_method: str,
    file_path: str,
    attempt_count: int,
    diff: str,
    replacement: ReplacementAttemptOutcome,
) -> ApplyFixResult:
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
        predicate_trace=policy_state_trace(
            rule_id=str(context.get("rule_id")), before_trace_raw=None, after_trace_raw=None
        ),
    )
