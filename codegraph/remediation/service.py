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
from codegraph.policy.integration import (
    PolicyEvaluator,
    evaluate_bundle,
    evaluate_policies,
    load_policy_catalog,
    normalize_violation_payload,
)
from codegraph.remediation.capabilities import get_remediation_capability, rule_id_variants
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
    STRUCTURED_GENERATION_STOPS,
    build_generation_payload,
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
from codegraph.remediation.metrics import capture_raw_llm_output, extract_testcase_id, summarize_retry_error
from codegraph.remediation.planning import build_remediation_plan
from codegraph.remediation.prompting import (
    RemediationPromptTemplate,
    RemediationTaskSpec,
    build_remediation_response_format,
)
from codegraph.remediation.validation import (
    extract_assistant_content,
    extract_json_block,
    parse_structured_generation_response,
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
        self._llm_client = llm_client

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

    @staticmethod
    def _build_generation_payload(
        *,
        decision: Optional[str],
        edits: Optional[List[Dict[str, Any]]],
        replacement_method_lines: Optional[List[str]],
        replacement_method_code: Optional[str],
        reason: Optional[str],
        raw_response_valid: bool,
        schema_error: Optional[str],
    ) -> Dict[str, Any]:
        return build_generation_payload(
            decision=decision,
            edits=edits,
            replacement_method_lines=replacement_method_lines,
            replacement_method_code=replacement_method_code,
            reason=reason,
            raw_response_valid=raw_response_valid,
            schema_error=schema_error,
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
            return self._build_no_fix_response(
                violation_id=violation_id,
                context=context,
                reason=preflight_reason,
            )

        llm_output = self.propose_method_edits(context)
        updated_source = llm_output.get("replacement_method_code")
        generation = llm_output.get("generation")
        decision = llm_output.get("decision")
        reason = llm_output.get("reason")
        schema_error = llm_output.get("schema_error")
        if decision == "no_fix":
            return self._build_no_fix_response(
                violation_id=violation_id,
                context=context,
                reason=reason or "no safe minimal fix available",
            )

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
        max_attempts = max(1, max_attempts)
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
                "target_method": context.get("target_method") or target_method,
                "file_path": context.get("file_path") or file_path,
            }
        target_method = target_method or context.get("target_method")
        file_path = file_path or context.get("file_path")
        if not target_method or not file_path:
            return {
                "status": "INVALID",
                "error": "target_method and file_path are required to apply remediation",
                "violation_id": violation_id,
                "target_method": target_method,
                "file_path": file_path,
                "rule_id": context.get("rule_id"),
            }

        preflight_reason = self._preflight_fixability_reason(context)
        if preflight_reason:
            return self._build_no_fix_response(
                violation_id=violation_id,
                context=context,
                reason=preflight_reason,
                attempt_count=0,
            )

        resolved_path = self._resolve_file_path(file_path)
        if resolved_path is None:
            return {
                "status": "VERIFICATION_ERROR",
                "error": f"Could not resolve file path: {file_path}",
                "violation_id": violation_id,
                "target_method": target_method,
                "file_path": file_path,
                "rule_id": context.get("rule_id"),
            }

        original_content = resolved_path.read_text(encoding="utf-8")
        baseline_violations = context.get("baseline_violations") or []
        attempt_errors: List[str] = []
        updated_content = None
        original_method = None
        updated_method = None
        raw_output = None
        raw_capture_files: List[str] = []
        generation_payload: Optional[Dict[str, Any]] = None

        for attempt in range(max_attempts):
            llm_output = self.propose_method_edits(context, previous_errors=attempt_errors)
            updated_source = llm_output.get("replacement_method_code")
            updated_source_lines = llm_output.get("replacement_method_lines")
            raw_output = llm_output.get("raw_output")
            generation_payload = llm_output.get("generation")
            if not updated_source:
                if llm_output.get("decision") == "no_fix":
                    reason = llm_output.get("reason") or "no safe minimal fix available"
                    result = self._build_no_fix_response(
                        violation_id=violation_id,
                        context=context,
                        reason=reason,
                        attempt_count=attempt + 1,
                    )
                    result["errors"] = attempt_errors
                    return result
                schema_error = llm_output.get("schema_error")
                if schema_error:
                    attempt_errors.append(_summarize_retry_error(str(schema_error)))
                else:
                    attempt_errors.append("empty_edits")
                if settings.remediation_raw_capture_enabled and raw_output:
                    capture_path = capture_raw_llm_output(
                        raw_capture_dir,
                        extract_testcase_id(target_method),
                        attempt + 1,
                        extract_assistant_content(raw_output),
                    )
                    if capture_path:
                        raw_capture_files.append(capture_path)
                continue
            try:
                updated_content, original_method, updated_method = self._replace_method_in_source(
                    original_content,
                    updated_source_lines or [],
                    target_method,
                )
                break
            except ValueError as exc:
                attempt_errors.append(_summarize_retry_error(str(exc)))
                continue

        if not updated_content or not updated_method or not original_method:
            final_status = "REPLACEMENT_ERROR"
            final_error = "Failed to produce a valid method replacement"
            if generation_payload and generation_payload.get("raw_response_valid") is False:
                final_status = "GENERATION_ERROR"
                final_error = generation_payload.get("schema_error") or final_error
            return {
                "status": final_status,
                "error": final_error,
                "violation_id": violation_id,
                "target_method": target_method,
                "file_path": file_path,
                "rule_id": context.get("rule_id"),
                "attempt_count": min(max_attempts, len(attempt_errors)),
                "llm_output": raw_output,
                "errors": attempt_errors,
                "raw_capture_files": raw_capture_files,
                "generation": generation_payload,
            }

        diff = _unified_diff(original_method, updated_method, label=target_method)
        compilation = {
            "attempted": False,
            "success": False,
            "output_snippet": None,
            "skipped_reason": "No build system detected",
        }
        verification: Dict[str, Any] = {}
        apply_successful = False
        attempt_count = min(max_attempts, max(1, len(attempt_errors) + 1))
        disk_modified = False

        try:
            with tempfile.TemporaryDirectory() as tmp:
                _temp_root, temp_file_path, temp_build_root = self._prepare_temp_workspace(Path(tmp), resolved_path)
                temp_file_path.write_text(updated_content, encoding="utf-8")
                compilation = self._compile_project(temp_build_root, build_command=build_command)

                try:
                    # Keep filesystem + graph in sync for verification. Policy evaluation derives
                    # source snippets/analysis flags from the file_path on disk.
                    #
                    # In dry_run, we restore the file at the end.
                    #
                    # Set disk_modified before writing so we attempt restoration even if the
                    # write fails after truncating the file.
                    disk_modified = True
                    resolved_path.write_text(updated_content, encoding="utf-8")
                    process_single_file_content(file_path, updated_content)
                except Exception as exc:  # pragma: no cover - runtime guard
                    if LOGGER.isEnabledFor(logging.DEBUG):
                        LOGGER.exception("Failed to re-ingest updated file: %s", exc)
                    else:
                        LOGGER.error("Failed to re-ingest updated file: %s", exc)
                    return {
                        "status": "VERIFICATION_ERROR",
                        "error": str(exc),
                        "violation_id": violation_id,
                        "target_method": target_method,
                        "file_path": file_path,
                        "rule_id": context.get("rule_id"),
                        "updated_source_code": updated_method,
                        "diff": diff,
                        "compilation": compilation,
                        "generation": generation_payload,
                    }

                evaluator = PolicyEvaluator()
                after_eval = evaluator.evaluate(target_method)
                if after_eval.get("error"):
                    verification = {
                        "error": after_eval.get("error"),
                        "baseline": baseline_violations,
                        "after": after_eval.get("violations") or [],
                    }
                else:
                    verification = _build_verification_summary(
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
                if not apply_successful:
                    process_single_file_content(file_path, original_content)
        except Exception as exc:  # pragma: no cover - runtime guard
            if LOGGER.isEnabledFor(logging.DEBUG):
                LOGGER.exception("Apply remediation failed: %s", exc)
            else:
                LOGGER.error("Apply remediation failed: %s", exc)
            return {
                "status": "VERIFICATION_ERROR",
                "error": str(exc),
                "violation_id": violation_id,
                "target_method": target_method,
                "file_path": file_path,
                "rule_id": context.get("rule_id"),
                "updated_source_code": updated_method,
                "diff": diff,
                "compilation": compilation,
                "generation": generation_payload,
            }
        finally:
            if disk_modified and (mode != "apply" or not apply_successful):
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
        return {
            "status": status,
            "violation_id": violation_id,
            "rule_id": context.get("rule_id"),
            "target_method": target_method,
            "file_path": file_path,
            "updated_source_code": updated_method,
            "diff": diff,
            "verification": verification,
            "compilation": compilation,
            "metadata": {
                "violation_id": violation_id,
                "rule_id": context.get("rule_id"),
                "target_method": target_method,
                "file_path": file_path,
                "attempt_count": attempt_count,
                "mode": mode,
            },
            "generation": generation_payload,
            "error": None if status == "OK" else (verification.get("error") or "Apply verification failed"),
        }

    def get_violation_context(
        self,
        violation_id: str,
        target_method: Optional[str] = None,
        file_path: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        workspace_root = os.path.abspath(settings.upload_dir)
        return gather_violation_context(
            violation_id,
            target_method=target_method,
            file_path=file_path,
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
        messages = RemediationPromptTemplate.build_messages(context=context, spec=spec, previous_errors=previous_errors)
        model = settings.remediation_llm_model or settings.llm_model
        temperature = (
            settings.remediation_llm_temperature
            if settings.remediation_llm_temperature is not None
            else settings.llm_temperature
        )
        max_tokens = (
            settings.remediation_llm_max_tokens
            if settings.remediation_llm_max_tokens is not None
            else settings.llm_max_tokens_remediation
        )
        ttl_seconds = (
            settings.remediation_llm_model_ttl_seconds
            if settings.remediation_llm_model_ttl_seconds is not None
            else settings.llm_model_ttl_seconds
        )

        try:
            response = self._llm_client(
                messages,
                model=model,
                temperature=temperature,
                max_tokens=max_tokens,
                ttl_seconds=ttl_seconds,
                stop=STRUCTURED_GENERATION_STOPS,
                response_format=build_remediation_response_format(),
                raise_on_error=True,
            )
        except TypeError:
            response = self._llm_client(messages)

        parsed = self._parse_structured_generation_response(
            response,
            target_method=context.get("target_method"),
            original_method_lines=(context.get("exact_method_source") or "").splitlines(),
            original_method_source=context.get("exact_method_source"),
            plan=context.get("remediation_plan"),
            rule_id=context.get("rule_id"),
        )
        parsed["raw_output"] = response
        parsed["generation"] = self._build_generation_payload(
            decision=parsed.get("decision"),
            edits=parsed.get("edits"),
            replacement_method_lines=parsed.get("replacement_method_lines"),
            replacement_method_code=parsed.get("replacement_method_code"),
            reason=parsed.get("reason"),
            raw_response_valid=bool(parsed.get("raw_response_valid")),
            schema_error=parsed.get("schema_error"),
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
