"""
llm_integration.py

Optional helper to enrich OPA/Rego violations with LLM-generated explanations and remediation advice.

This uses the OpenAI Python SDK v0.28.x (requests-based; no httpx). If `OPENAI_API_KEY` is not set
or the SDK is unavailable, it returns structured stubs so your pipeline still works without network.
"""

import os
from typing import Any, Dict, List


OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")


def _read_code_snippet(file_path: str, needle: str, before: int = 8, after: int = 24) -> str:
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        # simple heuristic: find first occurrence of method name
        idx_candidates = [i for i, line in enumerate(lines) if needle in line]
        if not idx_candidates:
            return ""
        idx = idx_candidates[0]
        start = max(0, idx - before)
        end = min(len(lines), idx + after)
        return "".join(lines[start:end])
    except Exception:
        return ""


def _build_prompt(violation: Dict[str, Any], code_snippet: str) -> List[Dict[str, str]]:
    system = (
        "You are a senior application security engineer. "
        "Explain why the finding violates ISO 27001 A.9.1.1 and how to fix it. "
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


def _call_openai(messages: List[Dict[str, str]], model: str = "gpt-4o-mini") -> str:
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return "[LLM unavailable: missing OPENAI_API_KEY]"
    try:
        import openai  # type: ignore
        openai.api_key = api_key
        resp = openai.ChatCompletion.create(model=model, messages=messages, temperature=0.2)
        return (resp.get("choices", [{}])[0].get("message", {}).get("content") or "").strip()
    except Exception as e:
        return f"[LLM unavailable or failed: {e}]"


def explain_policy_violations(
    violations: List[Dict[str, Any]],
    *,
    max_items: int = 10,
    model: str = "gpt-4o-mini",
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
        explanation = _call_openai(messages, model=model)
        results.append({
            "violation": v,
            "snippet": snippet,
            "explanation": explanation,
        })
    return results
