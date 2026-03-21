"""
Virtual remediation preview.

This module implements a closed-loop remediation flow for the thesis:
1) Fetch a violation + evidence from the existing policy evaluation.
2) Ask an LLM to propose bounded edits against the exact target method.
3) Reconstruct the updated method server-side.
4) Build a lightweight virtual graph context from that updated method.
5) Re-run the same OPA/Rego policies on the virtual bundle.

The original codebase, Neo4j graph, and filesystem remain untouched.
"""

from __future__ import annotations

import difflib
import logging
import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from codegraph.config import settings
from codegraph.ingestion.service import process_single_file_content
from codegraph.llm.client import generate_chat_completion
from codegraph.llm.schema.remediation import parse_structured_generation_response
from codegraph.llm.services.remediation_generation_service import RemediationGenerationService
from codegraph.llm.tasks.remediation import RemediationTaskSpec
from codegraph.policy.integration import (
    PolicyEvaluator,
    evaluate_bundle,
    evaluate_policies,
    load_policy_catalog,
    normalize_violation_payload,
)
from codegraph.remediation.capabilities import get_remediation_capability, rule_id_variants
from codegraph.remediation.confidence import (
    ConfidenceFeatures,
    assess_remediation_confidence,
)
from codegraph.remediation.context import (
    apply_annotation_heuristic,
    apply_fallback_graph_heuristics,
    apply_logger_heuristic,
    build_virtual_graph_context,
    dedupe_fields,
    gather_violation_context,
    sanitize_method_snippet,
)
from codegraph.remediation.contracts import (
    FIX_STRATEGIES,
    NO_FIX_PREFIX,
    build_no_fix_response,
)
from codegraph.remediation.editing import (
    apply_method_edits,
    extract_method_span,
    infer_method_end_line,
    normalize_type_name,
    params_match,
    parse_signature,
    replace_method_in_source,
    resolve_file_path,
)
from codegraph.remediation.apply_flow import execute_apply_fix
from codegraph.remediation.metrics import capture_raw_llm_output, extract_testcase_id, summarize_retry_error
from codegraph.remediation.planning import build_remediation_plan
from codegraph.remediation.validation import (
    extract_assistant_content,
    extract_json_block,
)
from codegraph.remediation.verification import (
    build_verification_summary,
    build_virtual_bundle,
    compile_project,
    detect_build_root,
    method_name_from_signature,
    prepare_temp_workspace,
)

LOGGER = logging.getLogger(__name__)


def _unified_diff(before: str, after: str, *, label: str = "method") -> str:
    diff = difflib.unified_diff(
        before.splitlines(),
        after.splitlines(),
        fromfile=f"{label} (before)",
        tofile=f"{label} (after)",
        lineterm="",
    )
    return "\n".join(diff)


def _extract_json_block(text: str) -> Optional[str]:
    return extract_json_block(text)


def _build_verification_summary(
    rule_id: Optional[str],
    baseline: Optional[List[Dict[str, Any]]],
    after: Optional[List[Dict[str, Any]]],
) -> Dict[str, Any]:
    return build_verification_summary(rule_id, baseline, after)


def _summarize_retry_error(error: str) -> str:
    return summarize_retry_error(error)


class RemediationService:
    """Preview-only remediation using virtual OPA evaluation."""

    _NO_FIX_PREFIX = NO_FIX_PREFIX
    _FIX_STRATEGIES: Dict[str, Dict[str, Any]] = FIX_STRATEGIES

    def __init__(self, *, llm_client=generate_chat_completion) -> None:
        self._generation_service = RemediationGenerationService(llm_client=llm_client)

    @staticmethod
    def _has_graph_context(context: Dict[str, Any]) -> bool:
        graph_context = ((context.get("evidence") or {}).get("graph_context")) or {}
        if not isinstance(graph_context, dict):
            return False
        keys = ("annotations", "uses_fields", "calls", "callers")
        return any(bool(graph_context.get(key)) for key in keys)

    def _build_confidence(
        self,
        *,
        context: Dict[str, Any],
        support_tier: str,
        decision: str,
        structured_valid: bool,
        attempt_count: int,
    ) -> Dict[str, Any]:
        assessment = assess_remediation_confidence(
            ConfidenceFeatures(
                support_tier=support_tier,
                decision=decision,
                structured_valid=structured_valid,
                has_exact_method_source=bool(context.get("exact_method_source")),
                has_graph_context=self._has_graph_context(context),
                attempt_count=max(1, int(attempt_count)),
            ),
            threshold_apply=settings.remediation_confidence_threshold_apply,
            threshold_review=settings.remediation_confidence_threshold_review,
            temperature=settings.remediation_confidence_temperature,
        )
        return {
            "score": assessment.score,
            "band": assessment.band,
            "threshold_apply": assessment.threshold_apply,
            "threshold_review": assessment.threshold_review,
            "rationale": assessment.rationale,
        }

    @classmethod
    def _rule_id_variants(cls, rule_id: str) -> List[str]:
        return rule_id_variants(rule_id)

    @classmethod
    def _resolve_fix_strategy(cls, rule_id: Optional[str]) -> Optional[Dict[str, Any]]:
        if not rule_id:
            return None
        capability = get_remediation_capability(rule_id, supported_rule_ids=cls._FIX_STRATEGIES.keys())
        if not capability.supported:
            return None
        for candidate in cls._rule_id_variants(rule_id):
            strategy = cls._FIX_STRATEGIES.get(candidate)
            if strategy is not None:
                return strategy
        return None

    @classmethod
    def _preflight_fixability_reason(cls, context: Dict[str, Any]) -> Optional[str]:
        rule_id = str(context.get("rule_id") or "")
        source_code = str(((context.get("evidence") or {}).get("source_code")) or "")
        source_lower = source_code.lower()

        if rule_id == "ISO-A.10-WEAK-CRYPTO":
            weak_cipher_literals = (
                "des/cbc/pkcs5padding",
                "desede/ecb/pkcs5padding",
                "aes/ecb/",
                '"rc4"',
                'cipher.getinstance("des")',
                'cipher.getinstance("rc4")',
            )
            has_supported_literal = any(literal in source_lower for literal in weak_cipher_literals)
            if not has_supported_literal or "cipher.getinstance" not in source_lower:
                return (
                    "weak-crypto remediation only supports explicit DES/RC4/AES-ECB literal subcases with local cipher context"
                )

        if rule_id == "ISO-A.10-WEAK-RANDOM":
            supported_patterns = (
                r"new\s+(?:java\.util\.)?random\s*\(",
                r"(?:java\.lang\.)?math\s*\.\s*random\s*\(",
                r"(?:java\.util\.concurrent\.)?threadlocalrandom\s*\.\s*current\s*\(",
                r"(?:java\.security\.)?securerandom\s*\.\s*getinstance\s*\(\s*\"sha1prng\"\s*\)",
            )
            if not any(re.search(pattern, source_lower) for pattern in supported_patterns):
                return (
                    "weak-random remediation only supports local Random/Math.random/ThreadLocalRandom/SHA1PRNG replacements"
                )

        return None

    @classmethod
    def _build_no_fix_response(
        cls,
        *,
        violation_id: str,
        context: Dict[str, Any],
        reason: str,
        attempt_count: int | None = None,
    ) -> Dict[str, Any]:
        return build_no_fix_response(
            violation_id=violation_id,
            context=context,
            reason=reason,
            attempt_count=attempt_count,
        )

    def preview_virtual_fix(
        self,
        violation_id: str,
        target_method: Optional[str] = None,
        file_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        context = self.get_violation_context(violation_id, target_method, file_path)
        if context is None:
            return {
                "status": "NOT_FOUND",
                "error": f"Violation {violation_id} not found",
                "violation_id": violation_id,
            }

        rule_id = context.get("rule_id")
        capability = get_remediation_capability(rule_id, supported_rule_ids=self._FIX_STRATEGIES.keys())
        if not capability.supported:
            return {
                "status": "INVALID",
                "error": capability.reason_code,
                "violation_id": violation_id,
                "rule_id": rule_id,
                "target_method": context.get("target_method"),
                "file_path": context.get("file_path"),
            }

        preflight_reason = self._preflight_fixability_reason(context)
        if preflight_reason:
            response = self._build_no_fix_response(
                violation_id=violation_id,
                context=context,
                reason=preflight_reason,
            )
            response["confidence"] = self._build_confidence(
                context=context,
                support_tier=capability.support_tier,
                decision="no_fix",
                structured_valid=True,
                attempt_count=1,
            )
            return response

        llm_output = self.propose_method_edits(context)
        updated_source = llm_output.get("replacement_method_code")
        generation = llm_output.get("generation")
        decision = llm_output.get("decision")
        reason = llm_output.get("reason")
        schema_error = llm_output.get("schema_error")
        confidence = self._build_confidence(
            context=context,
            support_tier=capability.support_tier,
            decision=str(decision or ""),
            structured_valid=bool((generation or {}).get("raw_response_valid")),
            attempt_count=1,
        )
        if decision == "no_fix":
            response = self._build_no_fix_response(
                violation_id=violation_id,
                context=context,
                reason=reason or "no safe minimal fix available",
            )
            response["confidence"] = confidence
            return response

        original_source = context.get("exact_method_source") or (context.get("evidence") or {}).get("source_code") or ""
        diff = _unified_diff(original_source, updated_source or "", label="method")
        if not updated_source:
            return {
                "status": "GENERATION_ERROR",
                "error": schema_error or "generation_error: missing edits",
                "violation_id": violation_id,
                "target_method": context.get("target_method"),
                "file_path": context.get("file_path"),
                "rule_id": rule_id,
                "generation": generation,
                "confidence": confidence,
            }

        base_graph = (context.get("evidence") or {}).get("graph_context") or {}
        virtual_graph = self.build_virtual_graph_context(updated_source, base_graph=base_graph)
        bundle = self._build_virtual_bundle(context, updated_source, virtual_graph)

        try:
            opa_raw = evaluate_bundle(bundle)
        except Exception as exc:  # pragma: no cover - runtime guard
            if LOGGER.isEnabledFor(logging.DEBUG):
                LOGGER.exception("OPA evaluation failed for virtual fix: %s", exc)
            else:
                LOGGER.error("OPA evaluation failed for virtual fix: %s", exc)
            return {
                "status": "VERIFICATION_ERROR",
                "error": str(exc),
                "violation_id": violation_id,
                "target_method": context.get("target_method"),
                "file_path": context.get("file_path"),
                "rule_id": context.get("rule_id"),
                "updated_source_code": updated_source,
                "generation": generation,
                "confidence": confidence,
            }

        normalized_output: List[Dict[str, Any]] = []
        for raw in opa_raw:
            normalized = normalize_violation_payload(raw)
            if not normalized:
                continue
            normalized_output.append(normalized)

        verification = _build_verification_summary(
            context.get("rule_id"),
            context.get("baseline_violations"),
            normalized_output,
        )
        opa_status = verification.get("target_rule_status")
        return {
            "status": "OK",
            "violation_id": violation_id,
            "rule_id": context.get("rule_id"),
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

    def apply_fix(
        self,
        violation_id: str,
        *,
        target_method: Optional[str] = None,
        file_path: Optional[str] = None,
        mode: str = "dry_run",
        max_attempts: int = 2,
        raw_capture_dir: Optional[str] = None,
        build_command: Optional[str] = None,
    ) -> Dict[str, Any]:
        return execute_apply_fix(
            service=self,
            violation_id=violation_id,
            target_method=target_method,
            file_path=file_path,
            mode=mode,
            max_attempts=max_attempts,
            raw_capture_dir=raw_capture_dir,
            build_command=build_command,
        )

    def get_violation_context(
        self,
        violation_id: str,
        target_method: Optional[str] = None,
        file_path: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        workspace_root = self._resolve_policy_workspace_root(file_path)
        return gather_violation_context(
            violation_id,
            target_method=target_method,
            file_path=file_path,
            policy_cache_key=workspace_root,
            evaluate_policies_fn=lambda: evaluate_policies(workspace_root=workspace_root),
            load_policy_catalog_fn=load_policy_catalog,
            policy_evaluator_cls=PolicyEvaluator,
            resolve_file_path_fn=self._resolve_file_path,
            extract_method_span_fn=self._extract_method_span,
            build_remediation_plan_fn=build_remediation_plan,
            logger=LOGGER,
        )

    def propose_method_edits(
        self,
        context: Dict[str, Any],
        previous_errors: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        rule_id = context.get("rule_id")
        strategy = self._resolve_fix_strategy(str(rule_id) if rule_id else None) or {}
        spec = RemediationTaskSpec(
            rule_id=str(rule_id or ""),
            objective=str(strategy.get("objective") or "").strip(),
            allowed_transformations=list(strategy.get("allowed_transformations") or []),
            non_goals=list(strategy.get("non_goals") or []),
            extra_examples=list(strategy.get("extra_examples") or []),
        )
        parsed = self._generation_service.propose_method_edits(
            context=context,
            spec=spec,
            previous_errors=previous_errors,
        )
        return parsed

    @staticmethod
    def _parse_structured_generation_response(
        response: Any,
        *,
        target_method: Optional[str] = None,
        original_method_lines: Optional[List[str]] = None,
        original_method_source: Optional[str] = None,
        plan: Any = None,
        rule_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        _ = original_method_source
        _ = rule_id
        return parse_structured_generation_response(
            response,
            target_method=target_method,
            original_method_lines=original_method_lines,
            plan=plan,
        )

    def build_virtual_graph_context(
        self,
        source_code: str,
        base_graph: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return build_virtual_graph_context(source_code, base_graph=base_graph)

    @staticmethod
    def _sanitize_method_snippet(source_code: str) -> str:
        return sanitize_method_snippet(source_code)

    @staticmethod
    def _apply_fallback_graph_heuristics(snippet: str, context: Dict[str, Any]) -> Dict[str, Any]:
        return apply_fallback_graph_heuristics(snippet, context)

    @staticmethod
    def _apply_logger_heuristic(snippet: str, context: Dict[str, Any]) -> Dict[str, Any]:
        return apply_logger_heuristic(snippet, context)

    @staticmethod
    def _apply_annotation_heuristic(snippet: str, context: Dict[str, Any]) -> Dict[str, Any]:
        return apply_annotation_heuristic(snippet, context)

    @staticmethod
    def _dedupe_fields(fields: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return dedupe_fields(fields)

    @staticmethod
    def _resolve_file_path(file_path: str) -> Optional[Path]:
        return resolve_file_path(file_path)

    @staticmethod
    def _resolve_policy_workspace_root(file_path: Optional[str] = None) -> str:
        if file_path:
            resolved = resolve_file_path(file_path)
            if resolved is not None:
                return resolved.as_posix()
            return os.path.abspath(file_path)
        return os.path.abspath(settings.upload_dir)

    @staticmethod
    def _detect_build_root(source_path: Path) -> Optional[Path]:
        return detect_build_root(source_path)

    def _prepare_temp_workspace(self, temp_root: Path, source_path: Path) -> Tuple[Path, Path, Optional[Path]]:
        return prepare_temp_workspace(temp_root, source_path)

    @staticmethod
    def _compile_project(build_root: Optional[Path], build_command: Optional[str] = None) -> Dict[str, Any]:
        return compile_project(build_root, build_command=build_command, run_command=subprocess.run)

    @staticmethod
    def _parse_signature(signature: str) -> Tuple[str, List[str]]:
        return parse_signature(signature)

    @staticmethod
    def _normalize_type_name(type_name: str) -> str:
        return normalize_type_name(type_name)

    @classmethod
    def _params_match(cls, expected: List[str], actual: List[str]) -> bool:
        _ = cls
        return params_match(expected, actual)

    @classmethod
    def _extract_method_span(
        cls,
        source: str,
        target_method: str,
    ) -> Tuple[List[str], int, int, str]:
        _ = cls
        return extract_method_span(source, target_method)

    @classmethod
    def _apply_method_edits(
        cls,
        original_lines: List[str],
        edits: List[Dict[str, Any]],
        target_method: str,
    ) -> Tuple[List[str], str]:
        _ = cls
        return apply_method_edits(original_lines, edits, target_method)

    @classmethod
    def _replace_method_in_source(
        cls,
        source: str,
        updated_method_lines: List[str],
        target_method: str,
    ) -> Tuple[str, str, str]:
        _ = cls
        return replace_method_in_source(source, updated_method_lines, target_method)

    @staticmethod
    def _infer_method_end_line(lines: List[str], start_line: int) -> Optional[int]:
        return infer_method_end_line(lines, start_line)

    def _build_virtual_bundle(
        self,
        context: Dict[str, Any],
        updated_source: str,
        virtual_graph: Dict[str, Any],
    ) -> Dict[str, Any]:
        _ = self
        return build_virtual_bundle(context, updated_source, virtual_graph)

    @staticmethod
    def _method_name_from_signature(signature: Optional[str]) -> Optional[str]:
        return method_name_from_signature(signature)
