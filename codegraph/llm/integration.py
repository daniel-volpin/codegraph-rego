"""
llm_integration.py

Optional helper to enrich OPA/Rego violations with LLM-generated explanations and remediation advice.

This module delegates to `llm_client.generate_chat_completion`, which is backed by LiteLLM. Configure
providers via environment variables (see config.py) to connect to OpenAI, LM Studio, or any other
supported endpoint. If the LLM is unavailable, a fallback message is returned so the API does not fail.
"""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List

from codegraph.config import LLM_MODEL, LLM_CONCURRENCY
from codegraph.llm.client import generate_chat_completion
from codegraph.llm.explanation_prompting import build_explanation_prompt, build_explanation_response_format
from codegraph.common.snippet_utils import extract_code_snippet

STRUCTURED_EXPLANATION_STOPS = ["<|im_end|>", "<|endoftext|>"]


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


def _render_structured_explanation(content: str) -> str:
    text = (content or "").strip()
    if not text:
        return text
    for token in ("<|im_end|>", "<|endoftext|>"):
        text = text.replace(token, "")
    text = text.strip()
    if text.startswith("{"):
        end_idx = text.rfind("}")
        if end_idx != -1:
            text = text[: end_idx + 1]
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return text
    if not isinstance(payload, dict):
        return text

    citation = str(payload.get("citation") or "").strip()
    why = str(payload.get("why") or "").strip()
    fix = str(payload.get("fix") or "").strip()
    lines = []
    if citation:
        lines.append(f"Citation: {citation}")
    if why:
        lines.append(f"Why: {why}")
    if fix:
        lines.append(f"Fix: {fix}")
    return "\n".join(lines) if lines else text


def _method_name_from_signature(signature: Any) -> str:
    if not isinstance(signature, str):
        return ""
    text = signature.strip()
    if not text:
        return ""
    return text.split(".")[-1].split("(")[0]


def _explain_single_violation(violation: Dict[str, Any], *, model: str) -> Dict[str, Any]:
    evidence = violation.get("evidence") if isinstance(violation, dict) else None
    evidence = evidence if isinstance(evidence, dict) else {}
    signature = violation.get("method") or violation.get("target_method") or evidence.get("target_method") or ""
    method_name = _method_name_from_signature(signature)
    file_path = violation.get("file_path") or evidence.get("file_path") or ""
    snippet = _read_code_snippet(file_path, method_name)
    messages = _build_prompt(violation, snippet)
    explanation = _call_llm(messages, model=model)
    return {"violation": violation, "snippet": snippet, "explanation": explanation}


def explain_policy_violations(
    violations: List[Dict[str, Any]],
    *,
    max_items: int = 10,
    model: str = LLM_MODEL,
) -> List[Dict[str, Any]]:
    """
    For each violation, read a local code snippet and ask the LLM for a short explanation + fix.
    Violations are processed concurrently (LLM_CONCURRENCY threads).
    """

    subset = violations[:max_items]
    results: List[Dict[str, Any]] = [None] * len(subset)  # type: ignore[list-item]
    with ThreadPoolExecutor(max_workers=max(1, LLM_CONCURRENCY)) as pool:
        future_to_idx = {
            pool.submit(_explain_single_violation, v, model=model or LLM_MODEL): i for i, v in enumerate(subset)
        }
        for future in as_completed(future_to_idx):
            idx = future_to_idx[future]
            results[idx] = future.result()
    return results


def generate_policy_explanation(
    violation: Dict[str, Any],
    *,
    include_graph_context: bool = True,
    evidence_mode: str = "full",
    structured_output: bool = False,
    model: str = LLM_MODEL,
    max_tokens: int | None = None,
    raise_on_error: bool = False,
) -> str:
    """
    Generate a single explanation with optional graph context for evaluation runners.
    """
    messages = build_explanation_prompt(
        violation,
        include_graph_context=include_graph_context,
        evidence_mode=evidence_mode,
    )
    response = generate_chat_completion(
        messages,
        model=model or LLM_MODEL,
        max_tokens=max_tokens,
        stop=STRUCTURED_EXPLANATION_STOPS if structured_output else None,
        response_format=build_explanation_response_format() if structured_output else None,
        raise_on_error=raise_on_error,
    )
    return _render_structured_explanation(response) if structured_output else response
