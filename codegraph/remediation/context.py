from __future__ import annotations

import logging
import re
import time
from typing import Any

import javalang
from javalang.tree import MemberReference, MethodDeclaration, MethodInvocation

LOGGER = logging.getLogger(__name__)
_POLICY_CACHE: dict[str, Any] = {
    "timestamp": 0.0,
    "data": None,
}
_CACHE_TTL_SECONDS = 30.0


def format_numbered_lines(lines: list[str]) -> str:
    return "\n".join(f"{idx + 1}: {line}" for idx, line in enumerate(lines))


def cached_policy_evaluation(evaluate_policies_fn) -> dict[str, Any]:
    now = time.monotonic()
    cached = _POLICY_CACHE.get("data")
    if cached and now - _POLICY_CACHE.get("timestamp", 0.0) < _CACHE_TTL_SECONDS:
        return cached
    data = evaluate_policies_fn()
    _POLICY_CACHE["data"] = data
    _POLICY_CACHE["timestamp"] = now
    return data


def gather_violation_context(
    violation_id: str,
    *,
    target_method: str | None = None,
    file_path: str | None = None,
    evaluate_policies_fn,
    load_policy_catalog_fn,
    policy_evaluator_cls,
    resolve_file_path_fn,
    extract_method_span_fn,
    build_remediation_plan_fn,
    logger: logging.Logger = LOGGER,
) -> dict[str, Any] | None:
    result = cached_policy_evaluation(evaluate_policies_fn)
    if result.get("error"):
        logger.error("Policy evaluation failed while gathering context: %s", result["error"])
        return None
    violations = result.get("violations") or []
    catalog = load_policy_catalog_fn()
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
        baseline_violations: list[dict[str, Any]] | None = None
        if method:
            evaluator = policy_evaluator_cls()
            evaluation = evaluator.evaluate(method)
            baseline_violations = evaluation.get("violations") or []
            if evaluation.get("error"):
                logger.warning(
                    "Baseline evaluation failed for %s: %s",
                    method,
                    evaluation.get("error"),
                )
        exact_method_source = None
        numbered_method_source = None
        resolved_path = resolve_file_path_fn(violation.get("file_path") or "")
        if resolved_path is not None and method:
            try:
                file_source = resolved_path.read_text(encoding="utf-8")
                exact_lines, _, _, exact_snippet = extract_method_span_fn(file_source, method)
                exact_method_source = exact_snippet
                numbered_method_source = format_numbered_lines(exact_lines)
            except Exception as exc:
                logger.debug("Failed to extract exact method span for %s: %s", method, exc)
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
            "remediation_plan": build_remediation_plan_fn(exact_method_source or evidence.get("source_code") or ""),
        }
    return None


def sanitize_method_snippet(source_code: str) -> str:
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


def dedupe_fields(fields: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    deduped: list[dict[str, Any]] = []
    for field in fields:
        name = field.get("name")
        key = name or id(field)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(field)
    return deduped


def apply_annotation_heuristic(snippet: str, context: dict[str, Any]) -> dict[str, Any]:
    annotations = set(context.get("annotations") or [])
    for match in re.findall(r"@([A-Za-z_][A-Za-z0-9_$.]*)", snippet):
        simple = match.split(".")[-1].lstrip("@")
        if simple:
            annotations.add(simple)
    context["annotations"] = sorted(annotations)
    return context


def apply_logger_heuristic(snippet: str, context: dict[str, Any]) -> dict[str, Any]:
    calls = set(context.get("calls") or [])
    uses_fields = list(context.get("uses_fields") or [])
    for match in re.findall(r"\b(?:logger|log)\.([A-Za-z_][A-Za-z0-9_]*)\s*\(", snippet):
        calls.add(f"logger.{match}")
    if re.search(r"\b(?:logger|log)\.", snippet):
        uses_fields.append({"name": "logger", "type": "Logger", "class_fqn": None})
    context["calls"] = sorted(calls)
    context["uses_fields"] = dedupe_fields(uses_fields)
    return context


def apply_fallback_graph_heuristics(snippet: str, context: dict[str, Any]) -> dict[str, Any]:
    calls = set(context.get("calls") or [])
    uses_fields = list(context.get("uses_fields") or [])
    for match in re.findall(r"\b(?:logger|log)\.([A-Za-z_][A-Za-z0-9_]*)\s*\(", snippet):
        calls.add(f"logger.{match}")
    for matched_field in set(re.findall(r"\bthis\.([A-Za-z_][A-Za-z0-9_]*)", snippet)):
        uses_fields.append({"name": matched_field, "type": None, "class_fqn": None})
    if re.search(r"\b(?:logger|log)\.", snippet):
        uses_fields.append({"name": "logger", "type": "Logger", "class_fqn": None})
    context["uses_fields"] = dedupe_fields(uses_fields)
    context["calls"] = sorted(calls)
    return apply_annotation_heuristic(snippet, context)


def build_virtual_graph_context(source_code: str, base_graph: dict[str, Any] | None = None) -> dict[str, Any]:
    context: dict[str, Any] = {
        "annotations": list((base_graph or {}).get("annotations") or []),
        "uses_fields": list((base_graph or {}).get("uses_fields") or []),
        "calls": list((base_graph or {}).get("calls") or []),
        "callers": list((base_graph or {}).get("callers") or []),
    }
    if not source_code:
        return context

    snippet = sanitize_method_snippet(source_code)
    wrapped = f"class VirtualPreview {{\n{snippet}\n}}"
    try:
        tree = javalang.parse.parse(wrapped)
    except Exception as exc:  # pragma: no cover - parser guard
        LOGGER.warning("Failed to parse virtual method snippet: %s", exc)
        return apply_fallback_graph_heuristics(snippet, context)

    if not getattr(tree, "types", None):
        return apply_fallback_graph_heuristics(snippet, context)

    type_decl = tree.types[0]
    methods = getattr(type_decl, "methods", None) or []
    if not methods:
        return apply_fallback_graph_heuristics(snippet, context)

    method: MethodDeclaration = methods[0]
    ann_names = [
        (ann.name or "").split(".")[-1].lstrip("@")
        for ann in (method.annotations or [])
        if getattr(ann, "name", None)
    ]
    context["annotations"] = sorted({*context["annotations"], *ann_names})

    calls: set[str] = set(context["calls"])
    uses_fields: list[dict[str, Any]] = list(context["uses_fields"])
    for _, node in method:
        if isinstance(node, MethodInvocation):
            parts = [part for part in (node.qualifier, node.member) if part]
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
    context["uses_fields"] = dedupe_fields(uses_fields)
    context = apply_annotation_heuristic(snippet, context)
    context = apply_logger_heuristic(snippet, context)
    return context
