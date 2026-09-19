from __future__ import annotations

import logging
from typing import Any

from codegraph.java.fragments import (
    JavaFragmentError,
    invocation_call_name,
    method_field_use_facts,
    method_invocation_facts,
    parse_strict_method_fragment,
)

LOGGER = logging.getLogger(__name__)


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


def _base_graph_context(base_graph: dict[str, Any] | None) -> dict[str, Any]:
    graph = base_graph or {}
    return {
        "annotations": list(graph.get("annotations") or []),
        "uses_fields": list(graph.get("uses_fields") or []),
        "calls": list(graph.get("calls") or []),
        "callers": list(graph.get("callers") or []),
        "observed_calls": list(graph.get("observed_calls") or []),
    }


def build_virtual_graph_context(source_code: str, base_graph: dict[str, Any] | None = None) -> dict[str, Any]:
    context = _base_graph_context(base_graph)
    if not source_code:
        return context

    snippet = sanitize_method_snippet(source_code)
    try:
        fragment = parse_strict_method_fragment(snippet.encode("utf-8"), require_body=False)
    except JavaFragmentError as exc:
        LOGGER.warning("Failed to parse virtual method snippet with JDT: %s", exc)
        return context

    method = fragment.method
    observed_calls = list(method_invocation_facts(method))
    calls = {str(call) for call in context["calls"] if isinstance(call, str)}
    calls.update(invocation_call_name(fact) for fact in observed_calls)
    context["calls"] = sorted(call for call in calls if call)
    context["observed_calls"] = [*context["observed_calls"], *observed_calls]
    context["annotations"] = sorted({*context["annotations"], *method.annotation_names})
    context["uses_fields"] = dedupe_fields([*context["uses_fields"], *method_field_use_facts(method)])
    return context
