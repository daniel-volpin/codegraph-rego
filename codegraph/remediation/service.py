"""
Virtual remediation preview.

This module implements a closed-loop remediation flow for the thesis:
1) Fetch a violation + evidence from the existing policy evaluation.
2) Ask an LLM to propose bounded edits against the exact target method.
3) Reconstruct the updated method server-side.
4) Build a lightweight virtual graph context from that updated method.
5) Re-run the same OPA/Rego policies on the virtual bundle.
"""

from __future__ import annotations

import logging
import os
import subprocess
from pathlib import Path
from typing import Any

from codegraph.config import settings
from codegraph.llm.client import generate_chat_completion
from codegraph.llm.schema.remediation import parse_structured_generation_response
from codegraph.llm.services.remediation_generation_service import RemediationGenerationService
from codegraph.llm.tasks.remediation import RemediationTaskSpec
from codegraph.policy.integration import PolicyEvaluator, evaluate_bundle, evaluate_policies, load_policy_catalog
from codegraph.remediation.apply_flow import execute_apply_fix
from codegraph.remediation.capabilities import rule_id_variants
from codegraph.remediation.context import (
    ContextSourceRefusalError,
    build_virtual_graph_context,
    dedupe_fields,
    gather_violation_context,
    sanitize_method_snippet,
)
from codegraph.remediation.contracts import AGENTIC_FIX_STRATEGIES, NO_FIX_PREFIX
from codegraph.remediation.editing import apply_method_edits, extract_method_span, resolve_file_path, unified_diff
from codegraph.remediation.metrics import summarize_retry_error
from codegraph.remediation.planning import build_remediation_plan
from codegraph.remediation.preview_flow import (
    _assert_recheck_can_reproduce_evidence,
    _verify_non_opa_rule,
    execute_preview_virtual_fix,
)
from codegraph.remediation.service_helpers import (
    build_confidence,
    build_remediation_no_fix_response,
    has_graph_context,
    preflight_fixability_reason,
    resolve_fix_strategy,
)
from codegraph.remediation.validation import extract_json_block
from codegraph.remediation.verification import (
    build_verification_summary,
    build_virtual_bundle,
    compile_project,
    detect_build_root,
    method_name_from_signature,
    prepare_temp_workspace,
)

__all__ = [
    "RemediationService",
    "_assert_recheck_can_reproduce_evidence",
    "_extract_json_block",
    "_summarize_retry_error",
    "_unified_diff",
    "_verify_non_opa_rule",
    "evaluate_bundle",
]

LOGGER = logging.getLogger(__name__)


def _unified_diff(before: str, after: str, *, label: str = "method") -> str:
    return unified_diff(before, after, label=label)


def _extract_json_block(text: str) -> str | None:
    return extract_json_block(text)


def _build_verification_summary(
    rule_id: str | None,
    baseline: list[dict[str, Any]] | None,
    after: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    return build_verification_summary(rule_id, baseline, after)


def _summarize_retry_error(error: str) -> str:
    return summarize_retry_error(error)


class RemediationService:
    """Preview-only remediation using virtual OPA evaluation."""

    _NO_FIX_PREFIX = NO_FIX_PREFIX
    _FIX_STRATEGIES: dict[str, dict[str, Any]] = AGENTIC_FIX_STRATEGIES

    def __init__(self, *, llm_client=generate_chat_completion) -> None:
        self._generation_service = RemediationGenerationService(llm_client=llm_client)

    @staticmethod
    def _has_graph_context(context: dict[str, Any]) -> bool:
        return has_graph_context(context)

    def _build_confidence(
        self,
        *,
        context: dict[str, Any],
        support_tier: str,
        decision: str,
        structured_valid: bool,
        attempt_count: int,
    ) -> dict[str, Any]:
        return build_confidence(
            context=context,
            support_tier=support_tier,
            decision=decision,
            structured_valid=structured_valid,
            attempt_count=attempt_count,
        )

    @classmethod
    def _rule_id_variants(cls, rule_id: str) -> list[str]:
        return rule_id_variants(rule_id)

    @classmethod
    def _resolve_fix_strategy(cls, rule_id: str | None) -> dict[str, Any] | None:
        return resolve_fix_strategy(rule_id, cls._FIX_STRATEGIES)

    @classmethod
    def _preflight_fixability_reason(cls, context: dict[str, Any]) -> str | None:
        return preflight_fixability_reason(context)

    @classmethod
    def _build_no_fix_response(
        cls,
        *,
        violation_id: str,
        context: dict[str, Any],
        reason: str,
        attempt_count: int | None = None,
    ) -> dict[str, Any]:
        return build_remediation_no_fix_response(
            violation_id=violation_id,
            context=context,
            reason=reason,
            attempt_count=attempt_count,
        )

    def preview_virtual_fix(
        self,
        violation_id: str,
        method_key: str,
        file_path: str | None = None,
    ) -> dict[str, Any]:
        return execute_preview_virtual_fix(
            service=self,
            violation_id=violation_id,
            method_key=method_key,
            file_path=file_path,
        )

    def apply_fix(
        self,
        violation_id: str,
        *,
        method_key: str,
        file_path: str | None = None,
        mode: str = "dry_run",
        max_attempts: int = 2,
        raw_capture_dir: str | None = None,
        build_command: str | None = None,
        prompt_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        try:
            return execute_apply_fix(
                service=self,
                violation_id=violation_id,
                method_key=method_key,
                file_path=file_path,
                mode=mode,
                max_attempts=max_attempts,
                raw_capture_dir=raw_capture_dir,
                build_command=build_command,
                prompt_context=prompt_context,
            )
        except ContextSourceRefusalError as exc:
            return {
                "status": exc.status,
                "error": exc.reason,
                "violation_id": violation_id,
                "method_key": method_key,
                "file_path": file_path or exc.file_path,
            }

    def get_violation_context(
        self,
        violation_id: str,
        method_key: str,
        file_path: str | None = None,
    ) -> dict[str, Any] | None:
        if not method_key:
            return None
        workspace_root = self._resolve_policy_workspace_root(file_path)
        return gather_violation_context(
            violation_id,
            method_key=method_key,
            file_path=file_path,
            policy_cache_key=workspace_root,
            evaluate_policies_fn=lambda: evaluate_policies(workspace_root=workspace_root),
            load_policy_catalog_fn=load_policy_catalog,
            policy_evaluator_cls=PolicyEvaluator,
            resolve_file_path_fn=self._resolve_file_path,
            build_remediation_plan_fn=build_remediation_plan,
            logger=LOGGER,
        )

    def propose_method_edits(
        self,
        context: dict[str, Any],
        previous_errors: list[str] | None = None,
    ) -> dict[str, Any]:
        rule_id = context.get("rule_id")
        strategy = self._resolve_fix_strategy(str(rule_id) if rule_id else None) or {}
        spec = RemediationTaskSpec(
            rule_id=str(rule_id or ""),
            objective=str(strategy.get("objective") or "").strip(),
            allowed_transformations=list(strategy.get("allowed_transformations") or []),
            non_goals=list(strategy.get("non_goals") or []),
            extra_examples=list(strategy.get("extra_examples") or []),
        )
        return self._generation_service.propose_method_edits(
            context=context,
            spec=spec,
            previous_errors=previous_errors,
        )

    @staticmethod
    def _parse_structured_generation_response(
        response: Any,
        *,
        target_method: str | None = None,
        original_method_lines: list[str] | None = None,
        original_method_source: str | None = None,
        plan: Any = None,
        rule_id: str | None = None,
    ) -> dict[str, Any]:
        _ = (original_method_source, rule_id)
        return parse_structured_generation_response(
            response,
            target_method=target_method,
            original_method_lines=original_method_lines,
            plan=plan,
        )

    def build_virtual_graph_context(
        self,
        source_code: str,
        base_graph: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return build_virtual_graph_context(source_code, base_graph=base_graph)

    _sanitize_method_snippet = staticmethod(sanitize_method_snippet)
    _dedupe_fields = staticmethod(dedupe_fields)
    _resolve_file_path = staticmethod(resolve_file_path)
    _detect_build_root = staticmethod(detect_build_root)
    _extract_method_span = staticmethod(extract_method_span)
    _apply_method_edits = staticmethod(apply_method_edits)
    _method_name_from_signature = staticmethod(method_name_from_signature)

    @staticmethod
    def _resolve_policy_workspace_root(file_path: str | None = None) -> str:
        if file_path:
            resolved = resolve_file_path(file_path)
            if resolved is not None:
                return resolved.as_posix()
            return os.path.abspath(file_path)
        return os.path.abspath(settings.upload_dir)

    def _prepare_temp_workspace(self, temp_root: Path, source_path: Path) -> tuple[Path, Path, Path | None]:
        return prepare_temp_workspace(temp_root, source_path)

    @staticmethod
    def _compile_project(build_root: Path | None, build_command: str | None = None) -> dict[str, Any]:
        return compile_project(build_root, build_command=build_command, run_command=subprocess.run)

    def _build_virtual_bundle(
        self, context: dict[str, Any], updated_source: str, virtual_graph: dict[str, Any]
    ) -> dict[str, Any]:
        return build_virtual_bundle(context, updated_source, virtual_graph)
