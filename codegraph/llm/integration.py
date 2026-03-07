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
from typing import Any, Dict, List, Optional

from codegraph.config import LLM_MODEL, LLM_CONCURRENCY
from codegraph.llm.client import generate_chat_completion
from codegraph.llm.explanation_prompting import build_explanation_prompt, build_explanation_response_format
from codegraph.common.snippet_utils import extract_code_snippet

STRUCTURED_EXPLANATION_STOPS = ["<|im_end|>", "<|endoftext|>"]
STRUCTURED_EXPLANATION_FIELDS = ("citation", "why", "fix")


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


def _strip_structured_stop_tokens(content: str) -> str:
    text = (content or "").strip()
    for token in STRUCTURED_EXPLANATION_STOPS:
        text = text.replace(token, "")
    return text.strip()


def _extract_json_object(text: str) -> Optional[str]:
    start_idx = text.find("{")
    if start_idx == -1:
        return None
    depth = 0
    in_string = False
    escaped = False
    for idx in range(start_idx, len(text)):
        char = text[idx]
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[start_idx : idx + 1]
    return None


def _parse_structured_explanation(content: str) -> Optional[Dict[str, str]]:
    text = _strip_structured_stop_tokens(content)
    if not text:
        return None
    json_text = _extract_json_object(text)
    if json_text:
        try:
            payload = json.loads(json_text)
        except json.JSONDecodeError:
            payload = None
        if isinstance(payload, dict) and set(payload.keys()) == set(STRUCTURED_EXPLANATION_FIELDS):
            parsed: Dict[str, str] = {}
            for field in STRUCTURED_EXPLANATION_FIELDS:
                value = payload.get(field)
                if not isinstance(value, str):
                    return None
                normalized = value.strip()
                if not normalized:
                    return None
                parsed[field] = normalized
            return parsed

    lowered = text.lower()
    citation_idx = lowered.find("citation:")
    why_idx = lowered.find("why:")
    fix_idx = lowered.find("fix:")
    if citation_idx == -1 or why_idx == -1 or fix_idx == -1:
        return None
    if not (citation_idx < why_idx < fix_idx):
        return None

    citation = text[citation_idx + len("citation:") : why_idx].strip()
    why = text[why_idx + len("why:") : fix_idx].strip()
    fix = text[fix_idx + len("fix:") :].strip()
    if not citation or not why or not fix:
        return None
    return {"citation": citation, "why": why, "fix": fix}


def render_policy_explanation_structured(payload: Dict[str, str]) -> str:
    return "\n".join(
        [
            f"Citation: {payload['citation']}",
            f"Why: {payload['why']}",
            f"Fix: {payload['fix']}",
        ]
    )


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
        structured_output=structured_output,
    )
    response = generate_chat_completion(
        messages,
        model=model or LLM_MODEL,
        max_tokens=max_tokens,
        stop=STRUCTURED_EXPLANATION_STOPS if structured_output else None,
        response_format=build_explanation_response_format() if structured_output else None,
        raise_on_error=raise_on_error,
    )
    if not structured_output:
        return response
    parsed = _parse_structured_explanation(response)
    if parsed is None:
        raise ValueError("LLM returned an invalid structured explanation payload.")
    return render_policy_explanation_structured(parsed)


def generate_policy_explanation_structured(
    violation: Dict[str, Any],
    *,
    include_graph_context: bool = True,
    evidence_mode: str = "full",
    model: str = LLM_MODEL,
    max_tokens: int | None = None,
    raise_on_error: bool = False,
) -> Dict[str, str]:
    messages = build_explanation_prompt(
        violation,
        include_graph_context=include_graph_context,
        evidence_mode=evidence_mode,
        structured_output=True,
    )
    response = generate_chat_completion(
        messages,
        model=model or LLM_MODEL,
        max_tokens=max_tokens,
        stop=STRUCTURED_EXPLANATION_STOPS,
        response_format=build_explanation_response_format(),
        raise_on_error=raise_on_error,
    )
    parsed = _parse_structured_explanation(response)
    if parsed is None:
        raise ValueError("LLM returned an invalid structured explanation payload.")
    return parsed
