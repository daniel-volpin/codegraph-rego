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
import json
import logging
import re
import shlex
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import javalang
from javalang.tree import MemberReference, MethodDeclaration, MethodInvocation

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
from codegraph.remediation.prompting import (
    RemediationPromptTemplate,
    RemediationTaskSpec,
    build_remediation_response_format,
)

LOGGER = logging.getLogger(__name__)
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_POLICY_CACHE: Dict[str, Any] = {
    "timestamp": 0.0,
    "data": None,
}
_CACHE_TTL_SECONDS = 30.0
_STRUCTURED_GENERATION_FIELDS = {"decision", "edits", "reason"}
_STRUCTURED_GENERATION_STOPS = ["<|im_end|>", "<|endoftext|>"]


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
    if not text:
        return None
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    return text[start : end + 1]


def _extract_assistant_content(response: Any) -> str:
    if isinstance(response, str):
        return response
    if isinstance(response, dict):
        try:
            choices = response.get("choices") or []
            if choices and isinstance(choices[0], dict):
                message = choices[0].get("message") or {}
                content = message.get("content")
                if isinstance(content, str):
                    return content
        except Exception:  # pragma: no cover - defensive guard
            pass
    return str(response or "")


def _strip_structured_stop_tokens(text: str) -> str:
    raw = (text or "").strip()
    for token in _STRUCTURED_GENERATION_STOPS:
        raw = raw.replace(token, "")
    return raw.strip()


def _normalize_generated_method_text(text: str) -> str:
    normalized = (text or "").strip()
    if "\\n" in normalized and "\n" not in normalized:
        normalized = normalized.replace("\\r\\n", "\n").replace("\\n", "\n")
    if "\\t" in normalized and "\t" not in normalized:
        normalized = normalized.replace("\\t", "\t")
    return normalized.strip()


def _normalize_generated_lines(lines: Iterable[str]) -> List[str]:
    normalized_lines: List[str] = []
    for raw_line in lines:
        line = str(raw_line)
        line = line.replace("\r\n", "\n").replace("\r", "\n")
        if "\\n" in line and "\n" not in line:
            line = line.replace("\\n", "\n")
        for split_line in line.split("\n"):
            normalized_lines.append(split_line.rstrip("\r"))
    while normalized_lines and normalized_lines[-1].strip() == "":
        normalized_lines.pop()
    return normalized_lines


def _detect_multiline_literal_issue(lines: Iterable[str]) -> Optional[str]:
    in_block_comment = False
    for line in lines:
        in_string = False
        in_char = False
        escaped = False
        index = 0
        while index < len(line):
            char = line[index]
            nxt = line[index + 1] if index + 1 < len(line) else ""

            if in_block_comment:
                if char == "*" and nxt == "/":
                    in_block_comment = False
                    index += 2
                    continue
                index += 1
                continue

            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
                index += 1
                continue

            if in_char:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == "'":
                    in_char = False
                index += 1
                continue

            if char == "/" and nxt == "/":
                break
            if char == "/" and nxt == "*":
                in_block_comment = True
                index += 2
                continue
            if char == '"':
                in_string = True
                index += 1
                continue
            if char == "'":
                in_char = True
                index += 1
                continue
            index += 1

        if in_string:
            return "invalid_java_syntax: multiline_string_literal"
        if in_char:
            return "invalid_java_syntax: multiline_char_literal"
    return None


def _extract_target_method_identity(target_method: Optional[str]) -> Tuple[Optional[str], Optional[int]]:
    raw = (target_method or "").strip()
    if not raw:
        return None, None
    method_match = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*\((.*)\)", raw)
    if not method_match:
        return None, None
    method_name = method_match.group(1)
    params_block = method_match.group(2).strip()
    if not params_block:
        return method_name, 0
    return method_name, len([part for part in params_block.split(",") if part.strip()])


def _format_java_parse_error(exc: Exception) -> str:
    detail = str(exc).strip()
    if detail:
        return f"{exc.__class__.__name__}: {detail}"
    return exc.__class__.__name__


def _format_numbered_lines(lines: List[str]) -> str:
    return "\n".join(f"{idx + 1}: {line}" for idx, line in enumerate(lines))


def _parse_json_object_from_text(text: str) -> Optional[Dict[str, Any]]:
    raw = text.strip()
    if not raw:
        return None

    try:
        loaded = json.loads(raw)
        return loaded if isinstance(loaded, dict) else None
    except json.JSONDecodeError:
        pass

    extracted = _extract_json_block(raw)
    if extracted:
        try:
            loaded = json.loads(extracted)
            return loaded if isinstance(loaded, dict) else None
        except json.JSONDecodeError:
            pass

    decoder = json.JSONDecoder()
    in_string = False
    quote_char = ""
    escaped = False
    for idx, char in enumerate(raw):
        if in_string:
            if escaped:
                escaped = False
                continue
            if char == "\\":
                escaped = True
                continue
            if char == quote_char:
                in_string = False
            continue

        if char in ('"', "'"):
            in_string = True
            quote_char = char
            continue

        if char != "{":
            continue

        try:
            loaded, _ = decoder.raw_decode(raw[idx:])
        except json.JSONDecodeError:
            continue
        if isinstance(loaded, dict):
            return loaded
    return None


def _extract_testcase_id(value: Optional[str]) -> str:
    match = re.search(r"(BenchmarkTest\d+)", value or "")
    return match.group(1) if match else "unknown"


def _capture_raw_llm_output(
    output_dir: Optional[str],
    testcase_id: str,
    attempt: int,
    content: str,
) -> Optional[str]:
    if not output_dir or not content:
        return None
    safe_testcase = re.sub(r"[^A-Za-z0-9_.-]+", "_", testcase_id or "unknown")
    # Keep a stable filename for quick lookup, and an attempt-specific one for debugging.
    stable_path = Path(output_dir) / f"raw_llm_{safe_testcase}.txt"
    out_path = Path(output_dir) / f"raw_llm_{safe_testcase}_attempt{attempt}.txt"
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        stable_path.write_text(content, encoding="utf-8")
        out_path.write_text(content, encoding="utf-8")
        return out_path.as_posix()
    except Exception as exc:  # pragma: no cover - filesystem guard
        LOGGER.warning("Failed to capture raw LLM output to %s: %s", out_path, exc)
        return None


def _cached_policy_evaluation() -> Dict[str, Any]:
    now = time.monotonic()
    cached = _POLICY_CACHE.get("data")
    if cached and now - _POLICY_CACHE.get("timestamp", 0.0) < _CACHE_TTL_SECONDS:
        return cached
    data = evaluate_policies()
    _POLICY_CACHE["data"] = data
    _POLICY_CACHE["timestamp"] = now
    return data


def _violation_key(violation: Dict[str, Any]) -> str:
    return str(
        violation.get("violation_id") or violation.get("id") or violation.get("control") or violation.get("rule") or ""
    )


def _build_verification_summary(
    rule_id: Optional[str],
    baseline: Optional[Iterable[Dict[str, Any]]],
    after: Optional[Iterable[Dict[str, Any]]],
) -> Dict[str, Any]:
    baseline_list = list(baseline or [])
    after_list = list(after or [])
    baseline_ids = {_violation_key(v) for v in baseline_list if _violation_key(v)}
    after_ids = {_violation_key(v) for v in after_list if _violation_key(v)}
    new_ids = after_ids - baseline_ids
    new_violations = [v for v in after_list if _violation_key(v) in new_ids]
    remaining_violations = [v for v in after_list if _violation_key(v) in baseline_ids]
    target_rule_status = "PASS"
    if rule_id and rule_id in after_ids:
        target_rule_status = "FAIL"
    overall_status = "PASS" if target_rule_status == "PASS" and not new_violations else "FAIL"
    return {
        "target_rule_status": target_rule_status,
        "overall_status": overall_status,
        "baseline": baseline_list,
        "after": after_list,
        "new_violations": new_violations,
        "remaining_violations": remaining_violations,
    }


def _summarize_retry_error(error: str) -> str:
    text = (error or "").strip()
    lowered = text.lower()
    if not text:
        return "generation_error"
    if "edit_span_out_of_bounds" in lowered:
        return "edit_span_out_of_bounds"
    if "edit_original_mismatch" in lowered:
        return "edit_original_mismatch"
    if "edit_spans_overlap" in lowered:
        return "edit_spans_overlap"
    if "invalid_java_syntax" in lowered:
        return "invalid_java_syntax"
    if "method_name_mismatch" in lowered:
        return "method_name_mismatch"
    if "parameter_count_mismatch" in lowered:
        return "parameter_count_mismatch"
    if "edits" in lowered:
        return "empty_edits"
    if "valid method replacement" in lowered or "replace method" in lowered or "apply_edits" in lowered:
        return "replacement_not_found"
    if "invalid_method_shape" in lowered:
        return "invalid_method_shape"
    if "access_modifier" in lowered:
        return "missing_access_modifier"
    return text.splitlines()[0][:160]

class RemediationService:
    """Preview-only remediation using virtual OPA evaluation."""

    _NO_FIX_PREFIX = "NO_FIX:"
    _FIX_STRATEGIES: Dict[str, Dict[str, Any]] = {
        "ISO-A.10-WEAK-HASH": {
            "objective": "Replace weak hash usage (MD5) with SHA-256 with minimal edits.",
            "allowed_transformations": [
                'Replace MessageDigest.getInstance("MD5") with MessageDigest.getInstance("SHA-256").',
                "Replace DigestUtils.md5* usage with a SHA-256 equivalent only if it is already available in the existing codebase context.",
            ],
            "non_goals": [
                "Do not change the method signature.",
                "Do not refactor unrelated code or rename variables.",
                "Do not add new logging or unrelated security changes.",
            ],
            "extra_examples": [],
        },
        "ISO-A.10-WEAK-RANDOM": {
            "objective": "Replace insecure randomness usage with SecureRandom-based generation using minimal local edits.",
            "allowed_transformations": [
                "Replace new Random() with new java.security.SecureRandom() without changing the surrounding method signature.",
                "Replace Math.random() with a local java.security.SecureRandom().nextDouble() call when the randomness use is method-local.",
                'Replace SecureRandom.getInstance("SHA1PRNG") with new java.security.SecureRandom() when no algorithm-specific behavior is required.',
                "Replace ThreadLocalRandom.current() with a method-local java.security.SecureRandom instance when the randomness is used for security-sensitive values.",
            ],
            "non_goals": [
                "Do not refactor logic across methods or introduce shared state.",
                "Do not change the method signature.",
                "Do not add unrelated security changes or logging.",
            ],
            "extra_examples": [],
        },
        "ISO-A.10-WEAK-CRYPTO": {
            "objective": "Replace weak literal cipher usage with a strong alternative only when the method already contains enough local context for a safe minimal edit.",
            "allowed_transformations": [
                "Replace DES/RC4/AES-ECB literal patterns with a stronger cipher transformation while keeping edits local to the method evidence.",
                "If a safe minimal fix is not possible with the given evidence, return NO_FIX.",
            ],
            "non_goals": [
                "Do not invent key management, IV/nonce generation, protocol changes, or storage formats.",
                "Do not change the method signature.",
                "Do not refactor unrelated code.",
            ],
            "extra_examples": [],
        },
    }

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
    def _build_no_fix_response(cls, *, violation_id: str, context: Dict[str, Any], reason: str, attempt_count: int | None = None) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "status": "NO_FIX",
            "error": f"{cls._NO_FIX_PREFIX} {reason}",
            "violation_id": violation_id,
            "target_method": context.get("target_method"),
            "file_path": context.get("file_path"),
            "rule_id": context.get("rule_id"),
            "generation": {
                "decision": "no_fix",
                "edits": [],
                "replacement_method_lines": None,
                "replacement_method_code": None,
                "reason": reason,
                "raw_response_valid": True,
                "schema_error": None,
            },
        }
        if attempt_count is not None:
            payload["attempt_count"] = attempt_count
        return payload

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
        return {
            "decision": decision,
            "edits": edits,
            "replacement_method_lines": replacement_method_lines,
            "replacement_method_code": replacement_method_code,
            "reason": reason,
            "raw_response_valid": raw_response_valid,
            "schema_error": schema_error,
        }

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
            result = self._build_no_fix_response(
                violation_id=violation_id,
                context=context,
                reason=reason or "no safe minimal fix available",
            )
            return result

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
        updated_source = None
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
                if (
                    settings.remediation_raw_capture_enabled
                    and raw_output
                ):
                    capture_path = _capture_raw_llm_output(
                        raw_capture_dir,
                        _extract_testcase_id(target_method),
                        attempt + 1,
                        _extract_assistant_content(raw_output),
                    )
                    if capture_path:
                        raw_capture_files.append(capture_path)
                continue
            try:
                updated_content, original_method, updated_method = self._replace_method_in_source(
                    original_content, updated_source_lines or [], target_method
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
                final_error = (generation_payload.get("schema_error") or final_error)
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
                temp_root, temp_file_path, temp_build_root = self._prepare_temp_workspace(Path(tmp), resolved_path)
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
            # Ensure dry_run never leaves the user's workspace modified.
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

    # --- Context gathering -----------------------------------------------------
    def get_violation_context(
        self,
        violation_id: str,
        target_method: Optional[str] = None,
        file_path: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        result = _cached_policy_evaluation()
        if result.get("error"):
            LOGGER.error("Policy evaluation failed while gathering context: %s", result["error"])
            return None
        violations = result.get("violations") or []
        catalog = load_policy_catalog()
        for violation in violations:
            current_id = violation.get("violation_id") or violation.get("id")
            if not current_id or str(current_id) != str(violation_id):
                continue
            method = violation.get("target_method") or violation.get("method")
            path = violation.get("file_path")
            if target_method and method and target_method != method:
                continue
            if file_path and path and file_path != path:
                continue
            evidence = violation.get("evidence") or {}
            catalog_entry = catalog.get(current_id) if isinstance(catalog, dict) else None
            baseline_violations: Optional[List[Dict[str, Any]]] = None
            if method:
                evaluator = PolicyEvaluator()
                evaluation = evaluator.evaluate(method)
                baseline_violations = evaluation.get("violations") or []
                if evaluation.get("error"):
                    LOGGER.warning(
                        "Baseline evaluation failed for %s: %s",
                        method,
                        evaluation.get("error"),
                    )
            exact_method_source = None
            numbered_method_source = None
            resolved_path = self._resolve_file_path(violation.get("file_path") or "")
            if resolved_path is not None and method:
                try:
                    file_source = resolved_path.read_text(encoding="utf-8")
                    exact_lines, _, _, exact_snippet = self._extract_method_span(file_source, method)
                    exact_method_source = exact_snippet
                    numbered_method_source = _format_numbered_lines(exact_lines)
                except Exception as exc:
                    LOGGER.debug("Failed to extract exact method span for %s: %s", method, exc)
            return {
                "violation": violation,
                "target_method": violation.get("target_method") or violation.get("method"),
                "file_path": violation.get("file_path"),
                "rule_id": current_id,
                "evidence": evidence,
                "catalog_entry": catalog_entry,
                "baseline_violations": baseline_violations,
                "exact_method_source": exact_method_source,
                "numbered_method_source": numbered_method_source,
            }
        return None

    # --- LLM interaction --------------------------------------------------------
    def propose_method_edits(
        self, context: Dict[str, Any], previous_errors: Optional[List[str]] = None
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
                stop=_STRUCTURED_GENERATION_STOPS,
                response_format=build_remediation_response_format(),
                raise_on_error=True,
            )
        except TypeError:
            response = self._llm_client(messages)
        parsed = self._parse_structured_generation_response(
            response,
            target_method=context.get("target_method"),
            original_method_lines=(context.get("exact_method_source") or "").splitlines(),
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
    ) -> Dict[str, Any]:
        content = _strip_structured_stop_tokens(_extract_assistant_content(response))
        data = _parse_json_object_from_text(content)
        if data is None:
            return {
                "decision": None,
                "edits": None,
                "replacement_method_lines": None,
                "replacement_method_code": None,
                "reason": None,
                "raw_response_valid": False,
                "schema_error": "invalid_json: malformed remediation generation payload",
            }

        if set(data.keys()) != _STRUCTURED_GENERATION_FIELDS:
            return {
                "decision": None,
                "edits": None,
                "replacement_method_lines": None,
                "replacement_method_code": None,
                "reason": None,
                "raw_response_valid": False,
                "schema_error": "schema_mismatch: expected decision/edits/reason",
            }

        decision = data.get("decision")
        edits = data.get("edits")
        reason = data.get("reason")
        if decision not in {"apply_edits", "no_fix"}:
            return {
                "decision": None,
                "edits": None,
                "replacement_method_lines": None,
                "replacement_method_code": None,
                "reason": None,
                "raw_response_valid": False,
                "schema_error": "schema_mismatch: invalid_decision",
            }

        if not isinstance(edits, list):
            return {
                "decision": None,
                "edits": None,
                "replacement_method_lines": None,
                "replacement_method_code": None,
                "reason": None,
                "raw_response_valid": False,
                "schema_error": "schema_mismatch: edits must be array",
            }
        if not isinstance(reason, str):
            return {
                "decision": None,
                "edits": None,
                "replacement_method_lines": None,
                "replacement_method_code": None,
                "reason": None,
                "raw_response_valid": False,
                "schema_error": "schema_mismatch: reason must be string",
            }

        normalized_reason = reason.strip()

        if decision == "apply_edits":
            if not edits:
                return {
                    "decision": "apply_edits",
                    "edits": None,
                    "replacement_method_lines": None,
                    "replacement_method_code": None,
                    "reason": "",
                    "raw_response_valid": False,
                    "schema_error": "empty_edits",
                }
            if original_method_lines is None:
                return {
                    "decision": "apply_edits",
                    "edits": None,
                    "replacement_method_lines": None,
                    "replacement_method_code": None,
                    "reason": "",
                    "raw_response_valid": False,
                    "schema_error": "missing_original_method_context",
                }
            normalized_edits: List[Dict[str, Any]] = []
            for edit in edits:
                if not isinstance(edit, dict):
                    return {
                        "decision": "apply_edits",
                        "edits": None,
                        "replacement_method_lines": None,
                        "replacement_method_code": None,
                        "reason": "",
                        "raw_response_valid": False,
                        "schema_error": "schema_mismatch: edit must be object",
                    }
                required_keys = {"start_line", "end_line", "original_lines", "replacement_lines"}
                if set(edit.keys()) != required_keys:
                    return {
                        "decision": "apply_edits",
                        "edits": None,
                        "replacement_method_lines": None,
                        "replacement_method_code": None,
                        "reason": "",
                        "raw_response_valid": False,
                        "schema_error": "schema_mismatch: invalid_edit_shape",
                    }
                if not isinstance(edit.get("start_line"), int) or not isinstance(edit.get("end_line"), int):
                    return {
                        "decision": "apply_edits",
                        "edits": None,
                        "replacement_method_lines": None,
                        "replacement_method_code": None,
                        "reason": "",
                        "raw_response_valid": False,
                        "schema_error": "schema_mismatch: edit_line_bounds_must_be_int",
                    }
                original_lines = edit.get("original_lines")
                replacement_lines = edit.get("replacement_lines")
                if not isinstance(original_lines, list) or not isinstance(replacement_lines, list):
                    return {
                        "decision": "apply_edits",
                        "edits": None,
                        "replacement_method_lines": None,
                        "replacement_method_code": None,
                        "reason": "",
                        "raw_response_valid": False,
                        "schema_error": "schema_mismatch: edit_lines_must_be_array",
                    }
                if any(not isinstance(line, str) for line in original_lines + replacement_lines):
                    return {
                        "decision": "apply_edits",
                        "edits": None,
                        "replacement_method_lines": None,
                        "replacement_method_code": None,
                        "reason": "",
                        "raw_response_valid": False,
                        "schema_error": "schema_mismatch: edit_lines_must_contain_strings",
                    }
                normalized_edits.append(
                    {
                        "start_line": edit["start_line"],
                        "end_line": edit["end_line"],
                        "original_lines": _normalize_generated_lines(original_lines),
                        "replacement_lines": _normalize_generated_lines(replacement_lines),
                    }
                )

            try:
                reconstructed_lines, reconstructed_method = RemediationService._apply_method_edits(
                    list(original_method_lines),
                    normalized_edits,
                    str(target_method or ""),
                )
            except ValueError as exc:
                return {
                    "decision": "apply_edits",
                    "edits": normalized_edits,
                    "replacement_method_lines": None,
                    "replacement_method_code": None,
                    "reason": "",
                    "raw_response_valid": False,
                    "schema_error": str(exc),
                }

            return {
                "decision": decision,
                "edits": normalized_edits,
                "replacement_method_lines": reconstructed_lines,
                "replacement_method_code": reconstructed_method,
                "reason": "",
                "raw_response_valid": True,
                "schema_error": None,
            }

        if not normalized_reason:
            return {
                "decision": None,
                "edits": None,
                "replacement_method_lines": None,
                "replacement_method_code": None,
                "reason": None,
                "raw_response_valid": False,
                "schema_error": "schema_mismatch: no_fix requires reason",
            }
        return {
            "decision": decision,
            "edits": [],
            "replacement_method_lines": None,
            "replacement_method_code": None,
            "reason": normalized_reason,
            "raw_response_valid": True,
            "schema_error": None,
        }

    # --- Virtual graph extraction ---------------------------------------------------
    def build_virtual_graph_context(
        self, source_code: str, base_graph: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        context: Dict[str, Any] = {
            "annotations": list((base_graph or {}).get("annotations") or []),
            "uses_fields": list((base_graph or {}).get("uses_fields") or []),
            "calls": list((base_graph or {}).get("calls") or []),
            "callers": list((base_graph or {}).get("callers") or []),
        }
        if not source_code:
            return context

        snippet = self._sanitize_method_snippet(source_code)
        wrapped = f"class VirtualPreview {{\n{snippet}\n}}"
        try:
            tree = javalang.parse.parse(wrapped)
        except Exception as exc:  # pragma: no cover - parser guard
            LOGGER.warning("Failed to parse virtual method snippet: %s", exc)
            return self._apply_fallback_graph_heuristics(snippet, context)

        if not getattr(tree, "types", None):
            return self._apply_fallback_graph_heuristics(snippet, context)

        type_decl = tree.types[0]
        methods = getattr(type_decl, "methods", None) or []
        if not methods:
            return self._apply_fallback_graph_heuristics(snippet, context)

        method: MethodDeclaration = methods[0]
        ann_names = [
            (ann.name or "").split(".")[-1].lstrip("@")
            for ann in (method.annotations or [])
            if getattr(ann, "name", None)
        ]
        context["annotations"] = sorted({*context["annotations"], *ann_names})

        calls: set[str] = set(context["calls"])
        uses_fields: List[Dict[str, Any]] = list(context["uses_fields"])
        for _, node in method:
            if isinstance(node, MethodInvocation):
                parts = [p for p in (node.qualifier, node.member) if p]
                call = ".".join(parts) if parts else node.member
                if call:
                    calls.add(call)
                if node.qualifier and node.qualifier.lower() in {"logger", "log"}:
                    uses_fields.append({"name": node.qualifier, "type": "Logger", "class_fqn": None})
            elif isinstance(node, MemberReference):
                member = node.member
                if member:
                    uses_fields.append(
                        {
                            "name": member,
                            "type": "Logger" if member.lower().startswith("log") else None,
                            "class_fqn": None,
                        }
                    )

        context["calls"] = sorted(calls)
        context["uses_fields"] = self._dedupe_fields(uses_fields)
        context = self._apply_annotation_heuristic(snippet, context)
        context = self._apply_logger_heuristic(snippet, context)
        return context

    @staticmethod
    def _sanitize_method_snippet(source_code: str) -> str:
        lines = source_code.splitlines()
        while lines and (lines[0].strip() == "" or lines[0].strip() == "}"):
            lines.pop(0)
        idx = 0
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("@") or stripped.startswith(("public", "private", "protected")):
                idx = i
                break
        return "\n".join(lines[idx:])

    @staticmethod
    def _apply_fallback_graph_heuristics(snippet: str, context: Dict[str, Any]) -> Dict[str, Any]:
        calls = set(context.get("calls") or [])
        uses_fields = list(context.get("uses_fields") or [])
        for match in re.findall(r"\b(?:logger|log)\.([A-Za-z_][A-Za-z0-9_]*)\s*\(", snippet):
            calls.add(f"logger.{match}")
        for matched_field in set(re.findall(r"\bthis\.([A-Za-z_][A-Za-z0-9_]*)", snippet)):
            uses_fields.append({"name": matched_field, "type": None, "class_fqn": None})
        if re.search(r"\b(?:logger|log)\.", snippet):
            uses_fields.append({"name": "logger", "type": "Logger", "class_fqn": None})
        context["uses_fields"] = RemediationService._dedupe_fields(uses_fields)
        context["calls"] = sorted(calls)
        context = RemediationService._apply_annotation_heuristic(snippet, context)
        return context

    @staticmethod
    def _apply_logger_heuristic(snippet: str, context: Dict[str, Any]) -> Dict[str, Any]:
        calls = set(context.get("calls") or [])
        uses_fields = list(context.get("uses_fields") or [])
        for match in re.findall(r"\b(?:logger|log)\.([A-Za-z_][A-Za-z0-9_]*)\s*\(", snippet):
            calls.add(f"logger.{match}")
        if re.search(r"\b(?:logger|log)\.", snippet):
            uses_fields.append({"name": "logger", "type": "Logger", "class_fqn": None})
        context["calls"] = sorted(calls)
        context["uses_fields"] = RemediationService._dedupe_fields(uses_fields)
        return context

    @staticmethod
    def _apply_annotation_heuristic(snippet: str, context: Dict[str, Any]) -> Dict[str, Any]:
        annotations = set(context.get("annotations") or [])
        for match in re.findall(r"@([A-Za-z_][A-Za-z0-9_$.]*)", snippet):
            simple = match.split(".")[-1].lstrip("@")
            if simple:
                annotations.add(simple)
        context["annotations"] = sorted(annotations)
        return context

    @staticmethod
    def _dedupe_fields(fields: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen = set()
        deduped: List[Dict[str, Any]] = []
        for f in fields:
            name = f.get("name")
            key = name or id(f)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(f)
        return deduped

    # --- Apply helpers ------------------------------------------------------------
    @staticmethod
    def _resolve_file_path(file_path: str) -> Optional[Path]:
        path = Path(file_path)
        if path.is_file():
            return path
        java_root = Path(settings.java_root_dir)
        if not java_root.is_absolute():
            java_root = _PROJECT_ROOT / java_root
        candidate = java_root / file_path
        if candidate.is_file():
            return candidate
        candidate = _PROJECT_ROOT / file_path
        if candidate.is_file():
            return candidate
        return None

    @staticmethod
    def _detect_build_root(source_path: Path) -> Optional[Path]:
        build_files = {"pom.xml", "build.gradle", "build.gradle.kts"}
        for ancestor in source_path.parents:
            if any((ancestor / name).exists() for name in build_files):
                return ancestor
        for ancestor in [_PROJECT_ROOT, *_PROJECT_ROOT.parents]:
            if any((ancestor / name).exists() for name in build_files):
                return ancestor
        return None

    def _prepare_temp_workspace(self, temp_root: Path, source_path: Path) -> Tuple[Path, Path, Optional[Path]]:
        build_root = self._detect_build_root(source_path)
        if build_root and build_root.exists():
            target_root = temp_root / build_root.name
            shutil.copytree(build_root, target_root)
            try:
                relative = source_path.relative_to(build_root)
            except ValueError:
                relative = Path(source_path.name)
            temp_file_path = target_root / relative
            temp_file_path.parent.mkdir(parents=True, exist_ok=True)
            return target_root, temp_file_path, target_root
        temp_file_path = temp_root / source_path.name
        temp_file_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_path, temp_file_path)
        return temp_root, temp_file_path, None

    @staticmethod
    def _compile_project(build_root: Optional[Path], build_command: Optional[str] = None) -> Dict[str, Any]:
        if not build_root:
            return {
                "attempted": False,
                "success": False,
                "output_snippet": None,
                "skipped_reason": "No build system detected",
            }
        mvn_file = build_root / "pom.xml"
        gradle_file = build_root / "build.gradle"
        gradle_kts_file = build_root / "build.gradle.kts"
        if not any(path.exists() for path in [mvn_file, gradle_file, gradle_kts_file]):
            return {
                "attempted": False,
                "success": False,
                "output_snippet": None,
                "skipped_reason": "No build system detected",
            }

        if build_command:
            cmd = shlex.split(build_command)
        elif mvn_file.exists():
            cmd = ["mvn", "-q", "-DskipTests", "compile"]
        else:
            gradlew = build_root / "gradlew"
            if gradlew.exists():
                cmd = [gradlew.as_posix(), "-q", "compileJava"]
            else:
                cmd = ["gradle", "-q", "compileJava"]

        try:
            proc = subprocess.run(
                cmd,
                cwd=build_root,
                capture_output=True,
                text=True,
                timeout=120,
            )
        except FileNotFoundError as exc:
            return {
                "attempted": True,
                "success": False,
                "output_snippet": str(exc),
                "skipped_reason": "Build tool not available",
            }
        except subprocess.TimeoutExpired:
            return {
                "attempted": True,
                "success": False,
                "output_snippet": "Compilation timed out",
                "skipped_reason": "Timeout",
            }

        output = "\n".join([proc.stdout.strip(), proc.stderr.strip()]).strip()
        output_snippet = output[:2000] if output else None
        return {
            "attempted": True,
            "success": proc.returncode == 0,
            "output_snippet": output_snippet,
        }

    @staticmethod
    def _parse_signature(signature: str) -> Tuple[str, List[str]]:
        if not signature:
            return "", []
        base, _, params = signature.partition("(")
        method_name = base.split(".")[-1].strip()
        params = params.rsplit(")", 1)[0]
        param_types = [p.strip() for p in params.split(",") if p.strip()]
        return method_name, param_types

    @staticmethod
    def _normalize_type_name(type_name: str) -> str:
        return type_name.split(".")[-1].replace("[]", "").strip()

    @classmethod
    def _params_match(cls, expected: List[str], actual: List[str]) -> bool:
        if expected and len(expected) != len(actual):
            return False
        if not expected:
            return len(actual) == 0
        return all(cls._normalize_type_name(exp) == cls._normalize_type_name(act) for exp, act in zip(expected, actual))

    @classmethod
    def _extract_method_span(
        cls,
        source: str,
        target_method: str,
    ) -> Tuple[List[str], int, int, str]:
        try:
            tree = javalang.parse.parse(source)
        except Exception as exc:  # pragma: no cover - parser guard
            raise ValueError(f"Failed to parse source file: {exc}") from exc

        method_name, expected_params = cls._parse_signature(target_method)
        if not method_name:
            raise ValueError("Unable to parse target method signature")
        source_lines = source.splitlines()

        match = None
        for _, node in tree.filter(MethodDeclaration):
            if node.name != method_name:
                continue
            actual_params = [
                getattr(param.type, "name", str(param.type))
                for param in getattr(node, "parameters", [])
                if getattr(param, "type", None) is not None
            ]
            if not cls._params_match(expected_params, actual_params):
                continue
            match = node
            break

        if match is None:
            raise ValueError(f"Method {target_method} not found in source file")

        start_line = match.position.line if match.position else None
        if start_line is None:
            raise ValueError("Method position not available for replacement")
        annotation_lines = [
            ann.position.line
            for ann in getattr(match, "annotations", [])
            if getattr(ann, "position", None) and ann.position
        ]
        if annotation_lines:
            start_line = min([start_line, *annotation_lines])

        end_line = cls._infer_method_end_line(source_lines, start_line)
        if end_line is None:
            raise ValueError("Could not determine method end line for replacement")

        original_lines = source_lines[start_line - 1 : end_line]
        original_snippet = "\n".join(original_lines)
        return original_lines, start_line, end_line, original_snippet

    @classmethod
    def _apply_method_edits(
        cls,
        original_lines: List[str],
        edits: List[Dict[str, Any]],
        target_method: str,
    ) -> Tuple[List[str], str]:
        def resolve_edit_span(
            declared_start: int,
            expected_original: List[str],
        ) -> Tuple[int, int]:
            expected_length = len(expected_original)
            if declared_start < 1 or declared_start > len(original_lines) or expected_length == 0:
                raise ValueError("edit_span_out_of_bounds")

            direct_end = declared_start + expected_length - 1
            if direct_end <= len(original_lines):
                direct_slice = original_lines[declared_start - 1 : direct_end]
                if direct_slice == expected_original:
                    return declared_start, direct_end

            search_start = max(1, declared_start - 1)
            search_end = min(len(original_lines) - expected_length + 1, declared_start + 2)
            matches: List[int] = []
            for candidate_start in range(search_start, search_end + 1):
                candidate_end = candidate_start + expected_length - 1
                if original_lines[candidate_start - 1 : candidate_end] == expected_original:
                    matches.append(candidate_start)

            if len(matches) == 1:
                candidate_start = matches[0]
                return candidate_start, candidate_start + expected_length - 1
            raise ValueError("edit_original_mismatch")

        updated_lines = list(original_lines)
        previous_end = 0
        offset = 0
        for edit in edits:
            start_line = edit["start_line"]
            expected_original = edit["original_lines"]
            replacement_lines = edit["replacement_lines"]

            actual_start, actual_end = resolve_edit_span(start_line, expected_original)
            declared_end = edit["end_line"]
            if declared_end < start_line:
                raise ValueError("edit_span_out_of_bounds")
            if actual_start <= previous_end:
                raise ValueError("edit_spans_overlap")

            adjusted_start = actual_start - 1 + offset
            adjusted_end = actual_end + offset
            updated_lines[adjusted_start:adjusted_end] = replacement_lines
            offset += len(replacement_lines) - len(expected_original)
            previous_end = actual_end

        updated_snippet = "\n".join(updated_lines)
        multiline_literal_issue = _detect_multiline_literal_issue(updated_lines)
        if multiline_literal_issue:
            raise ValueError(multiline_literal_issue)

        wrapped_method = f"class RemediationCandidate {{\n{updated_snippet}\n}}"
        try:
            parsed_wrapper = javalang.parse.parse(wrapped_method)
            parsed_methods = [node for _, node in parsed_wrapper.filter(MethodDeclaration)]
        except Exception as exc:
            raise ValueError(f"invalid_java_syntax: {_format_java_parse_error(exc)}") from exc

        if len(parsed_methods) != 1:
            raise ValueError("invalid_method_shape: expected single method declaration")
        parsed_method = parsed_methods[0]
        if not set(parsed_method.modifiers or set()).intersection({"public", "private", "protected"}):
            raise ValueError("invalid_method_shape: missing access_modifier")

        expected_method_name, expected_parameter_count = _extract_target_method_identity(target_method)
        if expected_method_name and parsed_method.name != expected_method_name:
            raise ValueError("method_name_mismatch")
        if expected_parameter_count is not None and len(parsed_method.parameters or []) != expected_parameter_count:
            raise ValueError("parameter_count_mismatch")

        return updated_lines, updated_snippet

    @classmethod
    def _replace_method_in_source(cls, source: str, updated_method_lines: List[str], target_method: str) -> Tuple[str, str, str]:
        source_lines = source.splitlines()
        _, start_line, end_line, original_snippet = cls._extract_method_span(source, target_method)
        updated_snippet = "\n".join(updated_method_lines)
        new_lines = source_lines[: start_line - 1] + updated_method_lines + source_lines[end_line:]
        new_source = "\n".join(new_lines)
        return new_source, original_snippet, updated_snippet

    @staticmethod
    def _infer_method_end_line(lines: List[str], start_line: int) -> Optional[int]:
        brace_count = 0
        started = False
        for idx in range(start_line - 1, len(lines)):
            line = lines[idx]
            for char in line:
                if char == "{":
                    brace_count += 1
                    started = True
                elif char == "}":
                    brace_count -= 1
            if started and brace_count == 0:
                return idx + 1
        return None

    # --- Bundle builder -------------------------------------------------------------
    def _build_virtual_bundle(
        self, context: Dict[str, Any], updated_source: str, virtual_graph: Dict[str, Any]
    ) -> Dict[str, Any]:
        graph_context = {
            "annotations": virtual_graph.get("annotations") or [],
            "uses_fields": virtual_graph.get("uses_fields") or [],
            "calls": virtual_graph.get("calls") or [],
            "callers": virtual_graph.get("callers") or [],
        }
        evidence = context.get("evidence") or {}
        target_method = context.get("target_method")
        return {
            "target_method": target_method,
            "method_name": self._method_name_from_signature(target_method),
            "class_fqn": context.get("violation", {}).get("class_fqn"),
            "file_path": context.get("file_path"),
            "modifiers": context.get("violation", {}).get("modifiers") or [],
            "source_code": updated_source,
            "graph_context": graph_context,
            "vector_context": evidence.get("vector_context") or [],
        }

    @staticmethod
    def _method_name_from_signature(signature: Optional[str]) -> Optional[str]:
        if not signature:
            return None
        base = signature.split("(")[0]
        if not base:
            return None
        return base.split(".")[-1] or None
