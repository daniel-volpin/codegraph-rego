from __future__ import annotations

import logging
import re
import time
from typing import Any

import javalang
from javalang.tree import MemberReference, MethodDeclaration, MethodInvocation

LOGGER = logging.getLogger(__name__)
_POLICY_CACHE: dict[str, dict[str, Any]] = {}
_CACHE_TTL_SECONDS = 30.0


def format_numbered_lines(lines: list[str]) -> str:
    return "\n".join(f"{idx + 1}: {line}" for idx, line in enumerate(lines))


def clear_policy_evaluation_cache() -> None:
    _POLICY_CACHE.clear()


def cached_policy_evaluation(evaluate_policies_fn, *, cache_key: str | None = None) -> dict[str, Any]:
    now = time.monotonic()
    key = str(cache_key or "default")
    cached = _POLICY_CACHE.get(key)
    if cached and now - float(cached.get("timestamp", 0.0)) < _CACHE_TTL_SECONDS:
        return cached.get("data") or {}
    data = evaluate_policies_fn()
    _POLICY_CACHE[key] = {
        "timestamp": now,
        "data": data,
    }
    return data


def _violation_rule_id(violation: dict[str, Any]) -> str | None:
    value = violation.get("violation_id") or violation.get("id")
    return str(value) if value else None


def _violation_method(violation: dict[str, Any]) -> str | None:
    value = violation.get("target_method") or violation.get("method")
    return str(value) if value else None


def _violation_matches(
    violation: dict[str, Any],
    *,
    violation_id: str,
    target_method: str | None,
    file_path: str | None,
) -> bool:
    current_id = _violation_rule_id(violation)
    if current_id != str(violation_id):
        return False

    method = _violation_method(violation)
    path = violation.get("file_path")
    if target_method and method and target_method != method:
        return False
    return not (file_path and path and file_path != path)


def _evaluate_baseline_violations(policy_evaluator_cls, method: str | None, logger: logging.Logger) -> list[dict[str, Any]] | None:
    if not method:
        return None
    evaluator = policy_evaluator_cls()
    evaluation = evaluator.evaluate(method)
    if evaluation.get("error"):
        logger.warning("Baseline evaluation failed for %s: %s", method, evaluation.get("error"))
    return evaluation.get("violations") or []


def _extract_exact_method_source(
    violation: dict[str, Any],
    method: str | None,
    *,
    resolve_file_path_fn,
    extract_method_span_fn,
    logger: logging.Logger,
) -> tuple[str | None, str | None]:
    resolved_path = resolve_file_path_fn(violation.get("file_path") or "")
    if resolved_path is None or not method:
        return None, None
    try:
        file_source = resolved_path.read_text(encoding="utf-8")
        exact_lines, _, _, exact_snippet = extract_method_span_fn(file_source, method)
        return exact_snippet, format_numbered_lines(exact_lines)
    except Exception as exc:
        logger.debug("Failed to extract exact method span for %s: %s", method, exc)
        return None, None


def _context_payload(
    violation: dict[str, Any],
    *,
    rule_id: str,
    method: str | None,
    catalog_entry: Any,
    baseline_violations: list[dict[str, Any]] | None,
    exact_method_source: str | None,
    numbered_method_source: str | None,
    build_remediation_plan_fn,
) -> dict[str, Any]:
    evidence = violation.get("evidence") or {}
    return {
        "violation": violation,
        "target_method": method,
        "file_path": violation.get("file_path"),
        "rule_id": rule_id,
        "evidence": evidence,
        "catalog_entry": catalog_entry,
        "baseline_violations": baseline_violations,
        "exact_method_source": exact_method_source,
        "numbered_method_source": numbered_method_source,
        "remediation_plan": build_remediation_plan_fn(exact_method_source or evidence.get("source_code") or ""),
    }


def gather_violation_context(
    violation_id: str,
    *,
    target_method: str | None = None,
    file_path: str | None = None,
    policy_cache_key: str | None = None,
    evaluate_policies_fn,
    load_policy_catalog_fn,
    policy_evaluator_cls,
    resolve_file_path_fn,
    extract_method_span_fn,
    build_remediation_plan_fn,
    logger: logging.Logger = LOGGER,
) -> dict[str, Any] | None:
    result = cached_policy_evaluation(evaluate_policies_fn, cache_key=policy_cache_key)
    if result.get("error"):
        logger.error("Policy evaluation failed while gathering context: %s", result["error"])
        return None
    violations = result.get("violations") or []
    catalog = load_policy_catalog_fn()
    for violation in violations:
        if not isinstance(violation, dict):
            continue
        if not _violation_matches(violation, violation_id=violation_id, target_method=target_method, file_path=file_path):
            continue

        rule_id = _violation_rule_id(violation)
        if rule_id is None:
            continue
        method = _violation_method(violation)
        exact_method_source, numbered_method_source = _extract_exact_method_source(
            violation,
            method,
            resolve_file_path_fn=resolve_file_path_fn,
            extract_method_span_fn=extract_method_span_fn,
            logger=logger,
        )
        return _context_payload(
            violation,
            rule_id=rule_id,
            method=method,
            catalog_entry=catalog.get(rule_id) if isinstance(catalog, dict) else None,
            baseline_violations=_evaluate_baseline_violations(policy_evaluator_cls, method, logger),
            exact_method_source=exact_method_source,
            numbered_method_source=numbered_method_source,
            build_remediation_plan_fn=build_remediation_plan_fn,
        )
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


def _base_graph_context(base_graph: dict[str, Any] | None) -> dict[str, Any]:
    graph = base_graph or {}
    return {
        "annotations": list(graph.get("annotations") or []),
        "uses_fields": list(graph.get("uses_fields") or []),
        "calls": list(graph.get("calls") or []),
        "callers": list(graph.get("callers") or []),
    }


def _parse_virtual_method(snippet: str) -> MethodDeclaration | None:
    wrapped = f"class VirtualPreview {{\n{snippet}\n}}"
    try:
        tree = javalang.parse.parse(wrapped)
    except Exception as exc:  # pragma: no cover - parser guard
        LOGGER.warning("Failed to parse virtual method snippet: %s", exc)
        return None

    type_declarations = getattr(tree, "types", None) or []
    if not type_declarations:
        return None
    methods = getattr(type_declarations[0], "methods", None) or []
    return methods[0] if methods else None


def _method_annotation_names(method: MethodDeclaration) -> list[str]:
    return [
        (annotation.name or "").split(".")[-1].lstrip("@")
        for annotation in (method.annotations or [])
        if getattr(annotation, "name", None)
    ]


def _method_invocation_call(node: MethodInvocation) -> str | None:
    parts = [part for part in (node.qualifier, node.member) if part]
    if parts:
        return ".".join(parts)
    return node.member or None


def _member_reference_field(node: MemberReference) -> dict[str, Any] | None:
    member = node.member
    if not member:
        return None
    return {
        "name": member,
        "type": "Logger" if member.lower().startswith("log") else None,
        "class_fqn": None,
    }


def _graph_delta_from_method(method: MethodDeclaration, context: dict[str, Any]) -> dict[str, Any]:
    calls: set[str] = set(context["calls"])
    uses_fields: list[dict[str, Any]] = list(context["uses_fields"])

    for _, node in method:
        if isinstance(node, MethodInvocation):
            call = _method_invocation_call(node)
            if call:
                calls.add(call)
            if node.qualifier and node.qualifier.lower() in {"logger", "log"}:
                uses_fields.append({"name": node.qualifier, "type": "Logger", "class_fqn": None})
            continue
        if isinstance(node, MemberReference):
            field = _member_reference_field(node)
            if field is not None:
                uses_fields.append(field)

    return {
        "calls": sorted(calls),
        "uses_fields": dedupe_fields(uses_fields),
    }


def build_virtual_graph_context(source_code: str, base_graph: dict[str, Any] | None = None) -> dict[str, Any]:
    context = _base_graph_context(base_graph)
    if not source_code:
        return context

    snippet = sanitize_method_snippet(source_code)
    method = _parse_virtual_method(snippet)
    if method is None:
        return apply_fallback_graph_heuristics(snippet, context)

    context["annotations"] = sorted({*context["annotations"], *_method_annotation_names(method)})
    context.update(_graph_delta_from_method(method, context))
    context = apply_annotation_heuristic(snippet, context)
    context = apply_logger_heuristic(snippet, context)
    return context
