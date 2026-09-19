from __future__ import annotations

import logging
from typing import Any

from codegraph.benchmark_registry import evidence_source_for_rule_id
from codegraph.policy.engines import get_engine
from codegraph.policy.integration import evaluate_bundle, normalize_violation_payload
from codegraph.remediation.capabilities import get_remediation_capability
from codegraph.remediation.context import ContextSourceRefusalError
from codegraph.remediation.contracts import resolve_context_source_code
from codegraph.remediation.editing import unified_diff
from codegraph.remediation.verification import build_verification_summary

LOGGER = logging.getLogger(__name__)


def _assert_recheck_can_reproduce_evidence(context: dict[str, Any]) -> None:
    """Refuse a recheck that cannot see the evidence the finding was based on."""
    evidence = context.get("evidence") or {}
    config_context = evidence.get("config_context") or {}
    if config_context.get("resolved"):
        raise RuntimeError("candidate_reverification_requires_config_evidence")


def _verify_non_opa_rule(*, context: dict[str, Any], updated_source: str) -> list[dict[str, Any]]:
    """Re-check a candidate with the engine that owns its rule, when that is not OPA."""
    rule_id = str(context.get("rule_id") or "")
    engine = get_engine(evidence_source_for_rule_id(rule_id))
    if engine is None:
        return []

    source_bytes = context.get("source_bytes")
    original_method = context.get("exact_method_source")
    file_path = str(context.get("file_path") or "")
    if not source_bytes or not original_method or not updated_source:
        raise RuntimeError("candidate_reverification_inputs_unavailable")

    original_file = source_bytes.decode("utf-8")
    if original_method not in original_file:
        raise RuntimeError("candidate_method_not_found_in_source")
    candidate_file = original_file.replace(original_method, updated_source, 1)

    return engine.verify_candidate(
        rule_id=rule_id,
        candidate_file_source=candidate_file,
        source_file_name=file_path or "Candidate.java",
    )


def execute_preview_virtual_fix(
    service: Any,
    violation_id: str,
    method_key: str,
    file_path: str | None = None,
) -> dict[str, Any]:
    if not method_key:
        return {
            "status": "INVALID",
            "error": "method_key is required",
            "violation_id": violation_id,
            "method_key": method_key,
        }
    try:
        context = service.get_violation_context(violation_id, method_key=method_key, file_path=file_path)
    except ContextSourceRefusalError as exc:
        return {
            "status": exc.status,
            "error": exc.reason,
            "violation_id": violation_id,
            "method_key": method_key,
            "file_path": file_path or exc.file_path,
        }
    if context is None:
        searched_root = service._resolve_policy_workspace_root(file_path)
        return {
            "status": "NOT_FOUND",
            "error": f"Violation {violation_id} not found under workspace root {searched_root}",
            "hint": (
                "Policy re-evaluation is scoped to a workspace root. Without file_path that "
                "root defaults to the upload workspace, so a violation in a workspace ingested "
                "elsewhere is invisible. Pass file_path from the violation."
            ),
            "violation_id": violation_id,
            "method_key": method_key,
            "workspace_root": searched_root,
        }

    rule_id = context.get("rule_id")
    capability = get_remediation_capability(rule_id, supported_rule_ids=service._FIX_STRATEGIES.keys())
    if not capability.supported:
        return {
            "status": "INVALID",
            "error": capability.reason_code,
            "violation_id": violation_id,
            "rule_id": rule_id,
            "method_key": context.get("method_key"),
            "target_method": context.get("target_method"),
            "file_path": context.get("file_path"),
        }

    preflight_reason = service._preflight_fixability_reason(context)
    if preflight_reason:
        response = service._build_no_fix_response(
            violation_id=violation_id,
            context=context,
            reason=preflight_reason,
        )
        response["confidence"] = service._build_confidence(
            context=context,
            support_tier=capability.support_tier,
            decision="no_fix",
            structured_valid=True,
            attempt_count=1,
        )
        return response

    llm_output = service.propose_method_edits(context)
    updated_source = llm_output.get("replacement_method_code")
    generation = llm_output.get("generation")
    decision = llm_output.get("decision")
    reason = llm_output.get("reason")
    schema_error = llm_output.get("schema_error")
    confidence = service._build_confidence(
        context=context,
        support_tier=capability.support_tier,
        decision=str(decision or ""),
        structured_valid=bool((generation or {}).get("raw_response_valid")),
        attempt_count=1,
    )
    if decision == "no_fix":
        response = service._build_no_fix_response(
            violation_id=violation_id,
            context=context,
            reason=reason or "no safe minimal fix available",
        )
        response["confidence"] = confidence
        return response

    original_source = resolve_context_source_code(context)
    diff = unified_diff(original_source, updated_source or "", label="method")
    if not updated_source:
        return {
            "status": "GENERATION_ERROR",
            "error": schema_error or "generation_error: missing edits",
            "violation_id": violation_id,
            "method_key": context.get("method_key"),
            "target_method": context.get("target_method"),
            "file_path": context.get("file_path"),
            "rule_id": rule_id,
            "generation": generation,
            "confidence": confidence,
        }

    base_graph = (context.get("evidence") or {}).get("graph_context") or {}
    virtual_graph = service.build_virtual_graph_context(updated_source, base_graph=base_graph)
    bundle = service._build_virtual_bundle(context, updated_source, virtual_graph)

    try:
        opa_raw = evaluate_bundle(bundle)
    except Exception as exc:  # pragma: no cover - runtime guard
        _err = {"err": str(exc), "err_type": type(exc).__name__}
        if LOGGER.isEnabledFor(logging.DEBUG):
            LOGGER.exception("OPA evaluation failed for virtual fix", extra=_err)
        else:
            LOGGER.error("OPA evaluation failed for virtual fix", extra=_err)
        return {
            "status": "VERIFICATION_ERROR",
            "error": str(exc),
            "violation_id": violation_id,
            "method_key": context.get("method_key"),
            "target_method": context.get("target_method"),
            "file_path": context.get("file_path"),
            "rule_id": context.get("rule_id"),
            "updated_source_code": updated_source,
            "generation": generation,
            "confidence": confidence,
        }

    normalized_output: list[dict[str, Any]] = []
    for raw in opa_raw:
        normalized = normalize_violation_payload(raw)
        if not normalized:
            continue
        normalized_output.append(normalized)

    try:
        _assert_recheck_can_reproduce_evidence(context)
        normalized_output.extend(
            _verify_non_opa_rule(context=context, updated_source=updated_source or ""),
        )
    except Exception as exc:
        LOGGER.error("Candidate re-verification failed", extra={"err": str(exc)})
        return {
            "status": "VERIFICATION_ERROR",
            "error": f"candidate_reverification_failed: {exc}",
            "violation_id": violation_id,
            "method_key": context.get("method_key"),
            "target_method": context.get("target_method"),
            "file_path": context.get("file_path"),
            "rule_id": context.get("rule_id"),
            "updated_source_code": updated_source,
            "generation": generation,
            "confidence": confidence,
        }

    verification = build_verification_summary(
        context.get("rule_id"),
        context.get("baseline_violations"),
        normalized_output,
    )
    opa_status = verification.get("target_rule_status")
    return {
        "status": "OK",
        "violation_id": violation_id,
        "rule_id": context.get("rule_id"),
        "method_key": context.get("method_key"),
        "target_method": context.get("target_method"),
        "file_path": context.get("file_path"),
        "updated_source_code": updated_source,
        "opa_status": opa_status,
        "opa_details": normalized_output or opa_raw,
        "diff": diff,
        "verification": verification,
        "generation": generation,
        "confidence": confidence,
    }
