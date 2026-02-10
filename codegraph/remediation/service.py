"""
Virtual remediation preview.

This module implements a closed-loop "virtual fix" flow for the thesis:
1) Fetch a violation + evidence from the existing policy evaluation.
2) Ask an LLM to propose a full replacement method (no diffs).
3) Build a lightweight virtual graph context from that proposed method.
4) Re-run the same OPA/Rego policies on the virtual bundle.

The original codebase, Neo4j graph, and filesystem remain untouched.
"""

from __future__ import annotations

import difflib
import json
import logging
import re
import shutil
import subprocess
import tempfile
import textwrap
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

LOGGER = logging.getLogger(__name__)
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_POLICY_CACHE: Dict[str, Any] = {
    "timestamp": 0.0,
    "data": None,
}
_CACHE_TTL_SECONDS = 30.0


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
    for idx, char in enumerate(raw):
        if char != "{":
            continue
        try:
            loaded, _ = decoder.raw_decode(raw[idx:])
        except json.JSONDecodeError:
            continue
        if isinstance(loaded, dict):
            return loaded
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
        violation.get("violation_id")
        or violation.get("id")
        or violation.get("control")
        or violation.get("rule")
        or ""
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
    overall_status = "PASS" if not after_list else "FAIL"
    return {
        "target_rule_status": target_rule_status,
        "overall_status": overall_status,
        "baseline": baseline_list,
        "after": after_list,
        "new_violations": new_violations,
        "remaining_violations": remaining_violations,
    }


class RemediationService:
    """Preview-only remediation using virtual OPA evaluation."""

    def __init__(self, *, llm_client=generate_chat_completion) -> None:
        self._llm_client = llm_client

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

        llm_output = self.propose_full_method(context)
        updated_source = llm_output.get("updated_source_code")
        explanation = llm_output.get("explanation")
        original_source = (context.get("evidence") or {}).get("source_code") or ""
        diff = _unified_diff(original_source, updated_source or "", label="method")
        if not updated_source:
            return {
                "status": "ERROR",
                "error": "LLM did not return updated_source_code",
                "violation_id": violation_id,
                "target_method": context.get("target_method"),
                "file_path": context.get("file_path"),
                "rule_id": context.get("rule_id"),
            }

        base_graph = (context.get("evidence") or {}).get("graph_context") or {}
        virtual_graph = self.build_virtual_graph_context(updated_source, base_graph=base_graph)
        bundle = self._build_virtual_bundle(context, updated_source, virtual_graph)

        try:
            opa_raw = evaluate_bundle(bundle)
        except Exception as exc:  # pragma: no cover - runtime guard
            LOGGER.exception("OPA evaluation failed for virtual fix: %s", exc)
            return {
                "status": "ERROR",
                "error": str(exc),
                "violation_id": violation_id,
                "target_method": context.get("target_method"),
                "file_path": context.get("file_path"),
                "rule_id": context.get("rule_id"),
                "updated_source_code": updated_source,
                "explanation": explanation,
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
            "explanation": explanation,
            "opa_status": opa_status,
            "opa_details": normalized_output or opa_raw,
            "diff": diff,
            "verification": verification,
        }

    def apply_fix(
        self,
        violation_id: str,
        *,
        target_method: Optional[str] = None,
        file_path: Optional[str] = None,
        mode: str = "dry_run",
        max_attempts: int = 2,
    ) -> Dict[str, Any]:
        max_attempts = max(1, max_attempts)
        context = self.get_violation_context(violation_id, target_method, file_path)
        if context is None:
            return {
                "status": "NOT_FOUND",
                "error": f"Violation {violation_id} not found",
                "violation_id": violation_id,
            }
        target_method = target_method or context.get("target_method")
        file_path = file_path or context.get("file_path")
        if not target_method or not file_path:
            return {
                "status": "ERROR",
                "error": "target_method and file_path are required to apply remediation",
                "violation_id": violation_id,
                "target_method": target_method,
                "file_path": file_path,
                "rule_id": context.get("rule_id"),
            }

        resolved_path = self._resolve_file_path(file_path)
        if resolved_path is None:
            return {
                "status": "ERROR",
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

        for attempt in range(max_attempts):
            llm_output = self.propose_full_method(context, previous_errors=attempt_errors)
            updated_source = llm_output.get("updated_source_code")
            raw_output = llm_output.get("raw_output")
            if not updated_source:
                parse_error = llm_output.get("parse_error")
                if parse_error:
                    attempt_errors.append(str(parse_error))
                else:
                    attempt_errors.append("schema mismatch: missing updated_source_code")
                continue
            try:
                updated_content, original_method, updated_method = self._replace_method_in_source(
                    original_content, updated_source, target_method
                )
                break
            except ValueError as exc:
                attempt_errors.append(str(exc))
                continue

        if not updated_content or not updated_method or not original_method:
            return {
                "status": "ERROR",
                "error": "Failed to produce a valid method replacement",
                "violation_id": violation_id,
                "target_method": target_method,
                "file_path": file_path,
                "rule_id": context.get("rule_id"),
                "attempt_count": min(max_attempts, len(attempt_errors)),
                "llm_output": raw_output,
                "errors": attempt_errors,
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

        try:
            with tempfile.TemporaryDirectory() as tmp:
                temp_root, temp_file_path, temp_build_root = self._prepare_temp_workspace(
                    Path(tmp), resolved_path
                )
                temp_file_path.write_text(updated_content, encoding="utf-8")
                compilation = self._compile_project(temp_build_root)

                try:
                    process_single_file_content(file_path, updated_content)
                except Exception as exc:  # pragma: no cover - runtime guard
                    LOGGER.exception("Failed to re-ingest updated file: %s", exc)
                    return {
                        "status": "ERROR",
                        "error": str(exc),
                        "violation_id": violation_id,
                        "target_method": target_method,
                        "file_path": file_path,
                        "rule_id": context.get("rule_id"),
                        "updated_source_code": updated_method,
                        "diff": diff,
                        "compilation": compilation,
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
                if can_apply:
                    resolved_path.write_text(updated_content, encoding="utf-8")
                    apply_successful = True
                if not apply_successful:
                    process_single_file_content(file_path, original_content)
        except Exception as exc:  # pragma: no cover - runtime guard
            LOGGER.exception("Apply remediation failed: %s", exc)
            return {
                "status": "ERROR",
                "error": str(exc),
                "violation_id": violation_id,
                "target_method": target_method,
                "file_path": file_path,
                "rule_id": context.get("rule_id"),
                "updated_source_code": updated_method,
                "diff": diff,
                "compilation": compilation,
            }

        status = "OK"
        if verification.get("error"):
            status = "ERROR"
        elif verification.get("overall_status") == "FAIL" or verification.get(
            "target_rule_status"
        ) == "FAIL":
            status = "FAIL"
        if mode == "apply" and not apply_successful:
            status = "FAIL"
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
            "error": None
            if status == "OK"
            else (verification.get("error") or "Apply verification failed"),
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
            return {
                "violation": violation,
                "target_method": violation.get("target_method") or violation.get("method"),
                "file_path": violation.get("file_path"),
                "rule_id": current_id,
                "evidence": evidence,
                "catalog_entry": catalog_entry,
                "baseline_violations": baseline_violations,
            }
        return None

    # --- LLM interaction --------------------------------------------------------
    def propose_full_method(
        self, context: Dict[str, Any], previous_errors: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        violation = context.get("violation") or {}
        evidence = context.get("evidence") or {}
        catalog_entry = context.get("catalog_entry") or {}
        source_code = (evidence.get("source_code") or "").strip()
        graph_context = evidence.get("graph_context") or {}
        vector_context = evidence.get("vector_context") or []
        file_path = context.get("file_path") or "<unknown>"
        policy_reason = violation.get("reason") or violation.get("description") or ""
        policy_title = catalog_entry.get("title") if isinstance(catalog_entry, dict) else ""
        errors_note = "\n".join(previous_errors or [])

        system_prompt = (
            "You are a senior Java engineer improving code for ISO 27001 policy compliance. "
            "Use ONLY the provided evidence (source snippet, graph context, vector context, control metadata). "
            "Return STRICT JSON with keys: updated_source_code (a full replacement method with the SAME signature) "
            "and explanation (one or two sentences). Return only the method declaration and body "
            "(no leading/trailing braces or surrounding class). "
            "Preserve the method signature exactly, apply the minimal necessary change to satisfy the control, "
            "do not remove security checks, do not introduce new dependencies, and keep behavior stable. "
            "Output JSON only, no markdown fences or extra text."
        )
        if errors_note:
            system_prompt += " Adjust the method to address previous errors."

        user_sections = [
            f"Violation: {violation}",
            f"Policy: {policy_title or ''} — {policy_reason}",
            f"File path: {file_path}",
            f"Target method: {context.get('target_method') or 'unknown'}",
            "Source snippet:",
            "```java",
            source_code,
            "```",
            "Graph context:",
            json.dumps(graph_context, indent=2),
            "Similar methods:",
            json.dumps(vector_context, indent=2),
        ]
        if errors_note:
            user_sections.append(f"Previous errors:\n{errors_note}")

        response = self._llm_client(
            [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": "\n".join(user_sections)},
            ]
        )
        parsed = self._parse_llm_virtual_json(response)
        parsed["raw_output"] = response
        return parsed

    @staticmethod
    def _parse_llm_virtual_json(response: Any) -> Dict[str, Any]:
        content = _extract_assistant_content(response).strip()
        data = _parse_json_object_from_text(content)
        if data is None:
            extracted = _extract_json_block(content or "")
            if extracted is None:
                LOGGER.warning("LLM output did not contain JSON object: %s", (content or "")[:200])
                return {
                    "updated_source_code": None,
                    "explanation": None,
                    "parse_error": "invalid_json: no JSON object found",
                }
            LOGGER.warning("LLM output was not valid JSON for virtual fix: %s", extracted[:200])
            return {
                "updated_source_code": None,
                "explanation": None,
                "parse_error": "invalid_json: malformed JSON payload",
            }

        updated_source_code = (
            data.get("updated_source_code")
            or data.get("replacement_method_code")
            or data.get("source")
        )
        explanation = data.get("explanation") or data.get("summary")
        if not isinstance(updated_source_code, str) or not updated_source_code.strip():
            LOGGER.warning(
                "LLM output schema mismatch for virtual fix. Expected one of "
                "updated_source_code/replacement_method_code/source; got keys: %s",
                sorted(data.keys()),
            )
            return {
                "updated_source_code": None,
                "explanation": explanation if isinstance(explanation, str) else None,
                "parse_error": "schema mismatch: missing replacement code key",
            }
        return {
            "updated_source_code": updated_source_code,
            "explanation": explanation if isinstance(explanation, str) else None,
            "parse_error": None,
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
                    uses_fields.append(
                        {"name": node.qualifier, "type": "Logger", "class_fqn": None}
                    )
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
        import re

        calls = set(context.get("calls") or [])
        uses_fields = list(context.get("uses_fields") or [])
        for match in re.findall(r"\b(?:logger|log)\.([A-Za-z_][A-Za-z0-9_]*)\s*\(", snippet):
            calls.add(f"logger.{match}")
        for field in set(re.findall(r"\bthis\.([A-Za-z_][A-Za-z0-9_]*)", snippet)):
            uses_fields.append({"name": field, "type": None, "class_fqn": None})
        if re.search(r"\b(?:logger|log)\.", snippet):
            uses_fields.append({"name": "logger", "type": "Logger", "class_fqn": None})
        context["uses_fields"] = RemediationService._dedupe_fields(uses_fields)
        context["calls"] = sorted(calls)
        context = RemediationService._apply_annotation_heuristic(snippet, context)
        return context

    @staticmethod
    def _apply_logger_heuristic(snippet: str, context: Dict[str, Any]) -> Dict[str, Any]:
        import re

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
        import re

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
        for field in fields:
            name = field.get("name")
            key = name or id(field)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(field)
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

    def _prepare_temp_workspace(
        self, temp_root: Path, source_path: Path
    ) -> Tuple[Path, Path, Optional[Path]]:
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
    def _compile_project(build_root: Optional[Path]) -> Dict[str, Any]:
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

        if mvn_file.exists():
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
        return all(
            cls._normalize_type_name(exp) == cls._normalize_type_name(act)
            for exp, act in zip(expected, actual)
        )

    @classmethod
    def _replace_method_in_source(
        cls, source: str, updated_method: str, target_method: str
    ) -> Tuple[str, str, str]:
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

        original_snippet = "\n".join(source_lines[start_line - 1 : end_line])
        indent = re.match(r"\s*", source_lines[start_line - 1]).group(0)
        cleaned_updated = textwrap.dedent(updated_method).strip("\n")
        updated_lines = [
            f"{indent}{line}" if line.strip() else line for line in cleaned_updated.splitlines()
        ]
        updated_snippet = "\n".join(updated_lines)
        new_lines = source_lines[: start_line - 1] + updated_lines + source_lines[end_line:]
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
