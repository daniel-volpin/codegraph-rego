from __future__ import annotations

import difflib
import hashlib
import json
import logging
import tempfile
from pathlib import Path
from typing import Any

import javalang  # type: ignore[import-untyped]

from codegraph.config import settings
from codegraph.policy.integration import PolicyEvaluator
from codegraph.remediation.comparison import build_llm_outcome, build_shadow_lifecycle_outcome, compare_remediation
from codegraph.remediation.editing import read_source_preserving_format, write_source_preserving_format
from codegraph.remediation.registry import build_registry
from codegraph.remediation.result_models import (
    ArtifactKind,
    Disposition,
    LifecycleReasonCode,
    NearMissKind,
    PatchArtifact,
    ShadowError,
    ShadowRemediationLifecycle,
    TransformationStrategy,
    ValidatorResult,
    ValidatorState,
)
from codegraph.remediation.sql_shadow_plugin import JdbcSqlShadowPlugin
from codegraph.remediation.verification import build_build_validator, build_verification_summary, pipeline_verified

LOGGER = logging.getLogger(__name__)


def _diff(before: str, after: str, label: str) -> str:
    return "\n".join(
        difflib.unified_diff(
            before.splitlines(),
            after.splitlines(),
            fromfile=f"{label} (before)",
            tofile=f"{label} (after)",
            lineterm="",
        )
    )


def _language_from_context(context: dict[str, Any]) -> str:
    file_path = str(context.get("file_path") or "")
    return "java" if file_path.endswith(".java") else "unknown"


def _normalize_file_path(file_path: str) -> str:
    path = Path(file_path)
    parts = list(path.parts)
    for marker in ("src", "uploaded_code"):
        if marker in parts:
            return Path(*parts[parts.index(marker) :]).as_posix()
    return path.name or path.as_posix().lstrip("/")


def _shadow_reproducibility_key(context: dict[str, Any], payload: dict[str, Any]) -> str:
    normalized = {
        "rule_id": str(context.get("rule_id") or "unknown"),
        "file_path": _normalize_file_path(str(context.get("file_path") or "unknown")),
        "target_method": str(context.get("target_method") or "unknown"),
        "source": str(context.get("exact_method_source") or ""),
        "payload": payload,
    }
    encoded = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _java_parse_validator(updated_source_code: str) -> ValidatorResult:
    try:
        javalang.parse.parse(updated_source_code)
    except Exception as exc:
        return ValidatorResult(
            validator_id="pipeline.java_parse",
            state=ValidatorState.FAIL,
            required=True,
            message=str(exc),
        )
    return ValidatorResult(validator_id="pipeline.java_parse", state=ValidatorState.PASS, required=True)


def _shadow_registry():
    plugins = []
    if settings.remediation_shadow_sql_plugin_enabled:
        plugins.append(JdbcSqlShadowPlugin())
    return build_registry(plugins)


def maybe_attach_shadow_result(
    service: Any,
    *,
    context: dict[str, Any],
    authoritative_result: dict[str, Any],
    build_command: str | None = None,
) -> dict[str, Any]:
    if not settings.remediation_shadow_lifecycle_enabled:
        return authoritative_result

    response = dict(authoritative_result)
    try:
        lifecycle = run_shadow_lifecycle(service, context=context, build_command=build_command)
        if lifecycle is None:
            return response
        response["shadow_lifecycle"] = lifecycle.model_dump(mode="json")
        response["shadow_comparison"] = compare_remediation(
            context,
            build_shadow_lifecycle_outcome(lifecycle),
            build_llm_outcome(authoritative_result),
        ).model_dump(mode="json")
        return response
    except Exception as exc:  # pragma: no cover - fail-closed runtime guard
        LOGGER.exception("Shadow remediation lifecycle failed")
        response["shadow_lifecycle"] = build_shadow_error_lifecycle(context, str(exc)).model_dump(mode="json")
        return response


def build_shadow_error_lifecycle(context: dict[str, Any], message: str) -> ShadowRemediationLifecycle:
    strategy = TransformationStrategy.BOUNDED_DETERMINISTIC_TEXT
    payload = {
        "plugin_id": "shadow-runtime",
        "plugin_version": "1.0.0",
        "supported_rule_id": str(context.get("rule_id") or "unknown"),
        "language": _language_from_context(context),
        "transformation_strategy": strategy.value,
        "artifact_kind": ArtifactKind.NONE.value,
        "disposition": Disposition.ABSTAIN.value,
        "recommended_disposition": Disposition.ABSTAIN.value,
        "reason_codes": [LifecycleReasonCode.TRANSFORMATION_FAILURE.value],
        "shadow_error": ShadowError(code="shadow_exception", message=message).model_dump(mode="json"),
    }
    return ShadowRemediationLifecycle(
        plugin_id="shadow-runtime",
        plugin_version="1.0.0",
        supported_rule_id=str(context.get("rule_id") or "unknown"),
        language=_language_from_context(context),
        transformation_strategy=strategy,
        artifact_kind=ArtifactKind.NONE,
        disposition=Disposition.ABSTAIN,
        recommended_disposition=Disposition.ABSTAIN,
        reason_codes=[LifecycleReasonCode.TRANSFORMATION_FAILURE],
        reproducibility_key=_shadow_reproducibility_key(context, payload),
        shadow_error=ShadowError(code="shadow_exception", message=message),
    )


def run_shadow_lifecycle(
    service: Any,
    *,
    context: dict[str, Any],
    build_command: str | None = None,
) -> ShadowRemediationLifecycle | None:
    registry = _shadow_registry()
    plugin = registry.resolve(rule_id=str(context.get("rule_id") or ""), language=_language_from_context(context))
    if plugin is None:
        return None

    proposal = plugin.propose(context)
    proposal_patch = None
    if proposal.details.get("patch_artifact"):
        proposal_patch = PatchArtifact.model_validate(proposal.details["patch_artifact"])

    reason_codes = list(proposal.reason_codes)
    pipeline_checks: list[ValidatorResult] = []
    semantic_validators: list[ValidatorResult] = []
    patch_artifact = proposal_patch
    updated_method_source: str | None = None
    updated_source_code: str | None = None

    if proposal.artifact_kind == ArtifactKind.PATCH and proposal_patch is not None:
        resolved_path = service._resolve_file_path(str(context.get("file_path") or ""))
        if resolved_path is None:
            pipeline_checks.append(
                ValidatorResult(
                    validator_id="pipeline.target_file_anchor",
                    state=ValidatorState.FAIL,
                    required=True,
                    message="Could not resolve target file path.",
                )
            )
        else:
            source_text, source_encoding, source_newline = read_source_preserving_format(resolved_path)
            original_lines, _, _, original_method_source = service._extract_method_span(source_text, str(context.get("target_method") or ""))
            pipeline_checks.append(
                ValidatorResult(
                    validator_id="pipeline.structured_patch_validity",
                    state=ValidatorState.PASS if proposal_patch.edits else ValidatorState.FAIL,
                    required=True,
                )
            )
            try:
                updated_lines, updated_method_source = service._apply_method_edits(
                    original_lines,
                    proposal_patch.edits,
                    str(context.get("target_method") or ""),
                )
                updated_source_code, _, _ = service._replace_method_in_source(
                    source_text,
                    updated_lines,
                    str(context.get("target_method") or ""),
                )
                if updated_method_source is None:
                    raise ValueError("shadow patch application produced no updated method source")
                updated_method_source_nonnull = updated_method_source
                patch_artifact = PatchArtifact(
                    target_file=proposal_patch.target_file,
                    anchor_method=proposal_patch.anchor_method,
                    edits=proposal_patch.edits,
                    updated_source_code=updated_method_source_nonnull,
                    diff=_diff(
                        original_method_source,
                        updated_method_source_nonnull,
                        str(context.get("target_method") or "method"),
                    ),
                )
                pipeline_checks.extend(
                    [
                        ValidatorResult(validator_id="pipeline.target_file_anchor", state=ValidatorState.PASS, required=True),
                        ValidatorResult(validator_id="pipeline.patch_apply", state=ValidatorState.PASS, required=True),
                    ]
                )
                if proposal.patch_pattern is not None and proposal.patch_pattern.pipeline_verification.require_parse:
                    pipeline_checks.append(_java_parse_validator(updated_source_code))
            except Exception as exc:
                pipeline_checks.extend(
                    [
                        ValidatorResult(validator_id="pipeline.target_file_anchor", state=ValidatorState.PASS, required=True),
                        ValidatorResult(
                            validator_id="pipeline.patch_apply",
                            state=ValidatorState.FAIL,
                            required=True,
                            message=str(exc),
                        ),
                    ]
                )
                reason_codes.append(LifecycleReasonCode.TRANSFORMATION_FAILURE)

            if updated_source_code is not None:
                with tempfile.TemporaryDirectory() as tmp:
                    _, temp_file_path, temp_build_root = service._prepare_temp_workspace(Path(tmp), resolved_path)
                    write_source_preserving_format(temp_file_path, updated_source_code, source_encoding, source_newline)
                    compilation = service._compile_project(temp_build_root, build_command=build_command)
                    pipeline_checks.append(
                        build_build_validator(
                            build_requirement=proposal.patch_pattern.pipeline_verification.build_requirement,
                            build_root=temp_build_root,
                            compilation=compilation,
                        )
                    )
                    evaluator = PolicyEvaluator()
                    after_eval = evaluator.evaluate(
                        str(context.get("target_method") or ""),
                        source_path_override=temp_file_path.as_posix(),
                    )
                    if after_eval.get("error"):
                        pipeline_checks.append(
                            ValidatorResult(
                                validator_id="pipeline.policy_recheck_completed",
                                state=ValidatorState.FAIL,
                                required=True,
                                message=str(after_eval.get("error")),
                            )
                        )
                    else:
                        verification = build_verification_summary(
                            context.get("rule_id"),
                            context.get("baseline_violations"),
                            after_eval.get("violations") or [],
                        )
                        pipeline_checks.extend(
                            [
                                ValidatorResult(
                                    validator_id="pipeline.policy_recheck_completed",
                                    state=ValidatorState.PASS,
                                    required=True,
                                ),
                                ValidatorResult(
                                    validator_id="pipeline.target_rule_status",
                                    state=ValidatorState.PASS if verification.get("target_rule_status") == "PASS" else ValidatorState.FAIL,
                                    required=True,
                                    details={"target_rule_status": verification.get("target_rule_status")},
                                ),
                                ValidatorResult(
                                    validator_id="pipeline.overall_policy_status",
                                    state=ValidatorState.PASS if verification.get("overall_status") == "PASS" else ValidatorState.FAIL,
                                    required=True,
                                    details={"overall_status": verification.get("overall_status")},
                                ),
                            ]
                        )

        semantic_validators = plugin.evaluate_semantics(
            context=context,
            proposal=proposal,
            updated_method_source=updated_method_source,
        )

    if any(validator.required and validator.state != ValidatorState.PASS for validator in pipeline_checks):
        reason_codes.append(LifecycleReasonCode.PIPELINE_VERIFICATION_FAILURE)
    if any(validator.required and validator.state != ValidatorState.PASS for validator in semantic_validators):
        reason_codes.append(LifecycleReasonCode.SEMANTIC_VERIFICATION_FAILURE)
    if not proposal.project_policy_dependency_resolved:
        reason_codes.append(LifecycleReasonCode.UNRESOLVED_PROJECT_POLICY_DEPENDENCY)

    pipeline_ok = pipeline_verified(pipeline_checks)
    mandatory_semantic_pass = bool(semantic_validators) and all(
        validator.state == ValidatorState.PASS for validator in semantic_validators if validator.required
    )
    assurance_ok = pipeline_ok and proposal.evidence_complete and proposal.project_policy_dependency_resolved and mandatory_semantic_pass
    auto_apply_eligible = bool(proposal.patch_pattern and proposal.patch_pattern.auto_apply_capable and assurance_ok)
    recommended_disposition = Disposition.AUTO_APPLY if auto_apply_eligible else proposal.disposition
    transformation_strategy = (
        proposal.patch_pattern.transformation_strategy
        if proposal.patch_pattern is not None
        else TransformationStrategy.TYPED_STRUCTURED_EDITS
    )
    near_miss_raw = proposal.details.get("near_miss_classification")
    near_miss_classification = NearMissKind(near_miss_raw) if isinstance(near_miss_raw, str) and near_miss_raw else None
    lifecycle_payload = {
        "plugin_id": plugin.descriptor.plugin_id,
        "plugin_version": plugin.descriptor.plugin_version,
        "supported_rule_id": str(context.get("rule_id") or ""),
        "language": _language_from_context(context),
        "repair_pattern_id": proposal.patch_pattern.pattern_id if proposal.patch_pattern else None,
        "repair_pattern_version": proposal.patch_pattern.pattern_version if proposal.patch_pattern else None,
        "transformation_strategy": transformation_strategy.value,
        "artifact_kind": proposal.artifact_kind.value,
        "disposition": proposal.disposition.value,
        "recommended_disposition": recommended_disposition.value,
        "pipeline_verified": pipeline_ok,
        "assurance_verified": assurance_ok,
        "auto_apply_eligible": auto_apply_eligible,
        "evidence_complete": proposal.evidence_complete,
        "project_policy_dependency_resolved": proposal.project_policy_dependency_resolved,
        "patch_artifact": patch_artifact.model_dump(mode="json") if patch_artifact is not None else None,
        "executable_scaffold": proposal.executable_scaffold.model_dump(mode="json") if proposal.executable_scaffold is not None else None,
        "structured_repair_plan": proposal.structured_repair_plan.model_dump(mode="json") if proposal.structured_repair_plan is not None else None,
        "near_miss_classification": near_miss_classification.value if near_miss_classification else None,
        "reason_codes": [code.value for code in list(dict.fromkeys(reason_codes))],
        "pipeline_checks": [validator.model_dump(mode="json") for validator in pipeline_checks],
        "semantic_validators": [validator.model_dump(mode="json") for validator in semantic_validators],
    }
    return ShadowRemediationLifecycle(
        plugin_id=plugin.descriptor.plugin_id,
        plugin_version=plugin.descriptor.plugin_version,
        supported_rule_id=str(context.get("rule_id") or ""),
        language=_language_from_context(context),
        repair_pattern_id=proposal.patch_pattern.pattern_id if proposal.patch_pattern else None,
        repair_pattern_version=proposal.patch_pattern.pattern_version if proposal.patch_pattern else None,
        transformation_strategy=transformation_strategy,
        artifact_kind=proposal.artifact_kind,
        disposition=proposal.disposition,
        recommended_disposition=recommended_disposition,
        pipeline_verified=pipeline_ok,
        assurance_verified=assurance_ok,
        auto_apply_eligible=auto_apply_eligible,
        evidence_complete=proposal.evidence_complete,
        project_policy_dependency_resolved=proposal.project_policy_dependency_resolved,
        patch_artifact=patch_artifact,
        executable_scaffold=proposal.executable_scaffold,
        structured_repair_plan=proposal.structured_repair_plan,
        near_miss_classification=near_miss_classification,
        reason_codes=list(dict.fromkeys(reason_codes)),
        pipeline_checks=pipeline_checks,
        semantic_validators=semantic_validators,
        reproducibility_key=_shadow_reproducibility_key(context, lifecycle_payload),
    )