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

import json
import logging
from typing import Any, Dict, List, Optional

import javalang
from javalang.tree import MemberReference, MethodDeclaration, MethodInvocation

from codegraph.llm.client import generate_chat_completion
from codegraph.policy.integration import (
    evaluate_bundle,
    evaluate_policies,
    load_policy_catalog,
    normalize_violation_payload,
)

LOGGER = logging.getLogger(__name__)


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
        failing: List[Dict[str, Any]] = []
        for raw in opa_raw:
            normalized = normalize_violation_payload(raw)
            if not normalized:
                continue
            normalized_output.append(normalized)
            if (normalized.get("violation_id") or normalized.get("id")) == context.get("rule_id"):
                failing.append(normalized)

        opa_status = "PASS" if not failing else "FAIL"
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
        }

    # --- Context gathering -----------------------------------------------------
    def get_violation_context(
        self,
        violation_id: str,
        target_method: Optional[str] = None,
        file_path: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        result = evaluate_policies()
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
            return {
                "violation": violation,
                "target_method": violation.get("target_method") or violation.get("method"),
                "file_path": violation.get("file_path"),
                "rule_id": current_id,
                "evidence": evidence,
                "catalog_entry": catalog_entry,
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
            "Return STRICT JSON with keys: updated_source_code (a full replacement method with the SAME signature) "
            "and explanation (one or two sentences). Return only the method declaration and body "
            "(no leading/trailing braces or surrounding class). Do not include markdown fences."
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
    def _parse_llm_virtual_json(text: str) -> Dict[str, Any]:
        cleaned = text.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.strip("`")
            parts = cleaned.split("\n", 1)
            if len(parts) == 2:
                cleaned = parts[1]
        try:
            data = json.loads(cleaned)
            if isinstance(data, dict):
                return {
                    "updated_source_code": data.get("updated_source_code") or data.get("source"),
                    "explanation": data.get("explanation") or data.get("summary"),
                }
        except json.JSONDecodeError:
            LOGGER.warning("LLM output was not valid JSON for virtual fix: %s", cleaned[:200])
        return {"updated_source_code": None, "explanation": None}

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

