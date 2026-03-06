from __future__ import annotations

import json
from typing import Any, Dict, List

LEAN_SNIPPET_MAX_CHARS = 1200
LEAN_ANNOTATION_CAP = 5
LEAN_NOTABLE_CALLS_CAP = 3


def _dedupe_preserve_order(values: List[str]) -> List[str]:
    seen: set[str] = set()
    result: List[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _truncate_text(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + "\n[truncated]"


def _build_lean_graph_summary(graph_context: Dict[str, Any], analysis_flags: Dict[str, Any]) -> Dict[str, Any]:
    annotations = [item for item in (graph_context.get("annotations") or []) if isinstance(item, str) and item.strip()]
    calls = [item for item in (graph_context.get("calls") or []) if isinstance(item, str) and item.strip()]
    callers = [item for item in (graph_context.get("callers") or []) if isinstance(item, str) and item.strip()]
    uses_fields = graph_context.get("uses_fields") or []
    notable_calls = _dedupe_preserve_order(calls)[:LEAN_NOTABLE_CALLS_CAP]

    summary: Dict[str, Any] = {
        "calls_count": len(calls),
        "callers_count": len(callers),
        "uses_fields_count": len(uses_fields),
    }
    if annotations:
        summary["annotations"] = _dedupe_preserve_order(annotations)[:LEAN_ANNOTATION_CAP]
    if notable_calls:
        summary["notable_calls"] = notable_calls
    compact_flags = {key: value for key, value in analysis_flags.items() if value}
    if compact_flags:
        summary["analysis_flags"] = compact_flags
    return summary


def build_explanation_evidence(
    violation: Dict[str, Any],
    *,
    include_graph_context: bool = True,
    evidence_mode: str = "full",
) -> Dict[str, Any]:
    evidence = violation.get("evidence") or {}
    file_path = evidence.get("file_path") or violation.get("file_path")
    target_method = evidence.get("target_method") or violation.get("target_method")
    start_line = evidence.get("start_line")
    end_line = evidence.get("end_line")
    source_code = evidence.get("source_code") or ""
    graph_context = evidence.get("graph_context") or {}
    vector_context = evidence.get("vector_context") or []
    analysis_flags = evidence.get("analysis_flags") or {}

    normalized_mode = evidence_mode if evidence_mode in {"full", "lean"} else "full"
    payload: Dict[str, Any] = {
        "file_path": file_path,
        "target_method": target_method,
        "start_line": start_line,
        "end_line": end_line,
        "source_code": source_code,
        "graph_context": graph_context if include_graph_context else {},
        "vector_context": vector_context if include_graph_context else [],
        "analysis_flags": analysis_flags,
        "evidence_mode": normalized_mode,
    }
    if normalized_mode == "lean":
        payload["source_code"] = _truncate_text(source_code, LEAN_SNIPPET_MAX_CHARS)
        payload["graph_context"] = (
            _build_lean_graph_summary(graph_context, analysis_flags) if include_graph_context else {}
        )
        payload["vector_context"] = []
    return payload


def build_explanation_prompt(
    violation: Dict[str, Any],
    *,
    include_graph_context: bool = True,
    evidence_mode: str = "full",
) -> List[Dict[str, str]]:
    payload = build_explanation_evidence(
        violation,
        include_graph_context=include_graph_context,
        evidence_mode=evidence_mode,
    )
    system = (
        "You are a senior application security engineer. "
        "Provide a concise explanation and remediation guidance. "
        "When evidence is provided, cite it explicitly using the exact file path and exact line range strings. "
        "Return only the final answer. Do not include thinking process, analysis steps, or chain-of-thought."
    )

    violation_summary = {k: v for k, v in violation.items() if k != "evidence"}
    user_lines = [f"Violation: {json.dumps(violation_summary, indent=2)}"]
    if include_graph_context:
        user_lines.append("Evidence bundle:")
        if payload.get("file_path"):
            user_lines.append(f"- file_path: {payload['file_path']}")
        if payload.get("target_method"):
            user_lines.append(f"- target_method: {payload['target_method']}")
        if payload.get("start_line") is not None and payload.get("end_line") is not None:
            user_lines.append(f"- lines: {payload['start_line']}-{payload['end_line']}")
        if payload.get("source_code"):
            user_lines.append("Source snippet:")
            user_lines.append("```java")
            user_lines.append(str(payload["source_code"]))
            user_lines.append("```")
        if payload.get("graph_context"):
            label = "Graph context" if evidence_mode == "full" else "Graph evidence summary"
            user_lines.append(f"{label}:")
            user_lines.append(json.dumps(payload["graph_context"], indent=2, sort_keys=True))
        if evidence_mode == "full" and payload.get("vector_context"):
            user_lines.append("Similar methods (FAISS):")
            user_lines.append(json.dumps(payload["vector_context"], indent=2))
        user_lines.append("Use the exact citation strings from the evidence bundle.")
        user_lines.append("If file path and lines are present, repeat them verbatim.")
        user_lines.append("Do not output Thinking Process, Analysis, or any preamble before the answer.")
    else:
        user_lines.append("Only the violation metadata is provided. Do not invent file paths or line numbers.")
        user_lines.append("Return only the final answer. Do not output Thinking Process or Analysis.")

    return [{"role": "system", "content": system}, {"role": "user", "content": "\n".join(user_lines)}]


def build_explanation_response_format() -> Dict[str, Any]:
    return {
        "type": "json_schema",
        "json_schema": {
            "name": "policy_explanation",
            "strict": True,
            "schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "citation": {
                        "type": "string",
                        "description": (
                            "Exact citation using the provided file path and, when available, the exact provided line range."
                        ),
                    },
                    "why": {
                        "type": "string",
                        "description": "One concise sentence explaining why the finding matters.",
                    },
                    "fix": {
                        "type": "string",
                        "description": "One concise sentence describing the concrete remediation.",
                    },
                },
                "required": ["citation", "why", "fix"],
            },
        },
    }
