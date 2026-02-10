"""
llm_integration.py

Optional helper to enrich OPA/Rego violations with LLM-generated explanations and remediation advice.

This module delegates to `llm_client.generate_chat_completion`, which is backed by LiteLLM. Configure
providers via environment variables (see config.py) to connect to OpenAI, LM Studio, or any other
supported endpoint. If the LLM is unavailable, a fallback message is returned so the API does not fail.
"""

from typing import Any, Dict, List
import json

from codegraph.config import LLM_MODEL
from codegraph.llm.client import generate_chat_completion
from codegraph.common.snippet_utils import extract_code_snippet

def _read_code_snippet(file_path: str, needle: str, before: int = 8, after: int = 24) -> str:
    return extract_code_snippet(file_path, needle, before=before, after=after)


def _build_prompt(violation: Dict[str, Any], code_snippet: str) -> List[Dict[str, str]]:
    system = (
        "You are a senior application security engineer. "
        "Explain why the finding violates the applicable ISO 27001 control and how to fix it. "
        "Be concise and actionable."
    )
    user = (
        f"Finding:\n{violation}\n\n"
        f"Code snippet (may be partial):\n" + (code_snippet or "<no snippet available>") + "\n\n"
        "Tasks:\n"
        "1) Brief risk summary.\n"
        "2) Why it violates the control.\n"
        "3) Concrete remediation steps (Java/Spring annotations, examples).\n"
    )
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def _call_llm(messages: List[Dict[str, str]], model: str) -> str:
    return generate_chat_completion(messages, model=model)


def explain_policy_violations(
    violations: List[Dict[str, Any]],
    *,
    max_items: int = 10,
    model: str = LLM_MODEL,
) -> List[Dict[str, Any]]:
    """
    For each violation, read a local code snippet and ask the LLM for a short explanation + fix.
    If the LLM is not configured, returns a stub with the snippet only.
    """
    results: List[Dict[str, Any]] = []
    for v in violations[:max_items]:
        method_name = v.get("method", "").split(".")[-1].split("(")[0]
        snippet = _read_code_snippet(v.get("file_path", "") or "", method_name)
        messages = _build_prompt(v, snippet)
        explanation = _call_llm(messages, model=model or LLM_MODEL)
        results.append({
            "violation": v,
            "snippet": snippet,
            "explanation": explanation,
        })
    return results


def generate_policy_explanation(
    violation: Dict[str, Any],
    *,
    include_graph_context: bool = True,
    model: str = LLM_MODEL,
) -> str:
    """
    Generate a single explanation with optional graph context for evaluation runners.
    """
    evidence = violation.get("evidence") or {}
    file_path = evidence.get("file_path") or violation.get("file_path")
    target_method = evidence.get("target_method") or violation.get("target_method")
    start_line = evidence.get("start_line")
    end_line = evidence.get("end_line")
    source_code = evidence.get("source_code") or ""
    graph_context = evidence.get("graph_context") or {}
    vector_context = evidence.get("vector_context") or []

    system = (
        "You are a senior application security engineer. "
        "Provide a concise explanation and remediation guidance. "
        "When evidence is provided, cite it explicitly (file path or line range)."
    )

    user_lines = [f"Violation: {json.dumps(violation, indent=2)}"]
    if include_graph_context:
        user_lines.append("Evidence bundle:")
        if file_path:
            user_lines.append(f"- file_path: {file_path}")
        if target_method:
            user_lines.append(f"- target_method: {target_method}")
        if start_line is not None and end_line is not None:
            user_lines.append(f"- lines: {start_line}-{end_line}")
        if source_code:
            user_lines.append("Source snippet:")
            user_lines.append("```java")
            user_lines.append(source_code)
            user_lines.append("```")
        if graph_context:
            user_lines.append("Graph context:")
            user_lines.append(json.dumps(graph_context, indent=2))
        if vector_context:
            user_lines.append("Similar methods:")
            user_lines.append(json.dumps(vector_context, indent=2))
        user_lines.append("Cite file paths or line ranges in your response.")
    else:
        user_lines.append("Only the violation text is provided. Do not invent file paths or line numbers.")

    messages = [{"role": "system", "content": system}, {"role": "user", "content": "\n".join(user_lines)}]
    return generate_chat_completion(messages, model=model or LLM_MODEL)
