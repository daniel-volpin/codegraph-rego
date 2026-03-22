from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Literal

from codegraph.common.snippet_utils import extract_code_snippet
from codegraph.config import settings
from codegraph.llm.client import generate_chat_completion
from codegraph.llm.schema.explanation import (
    STRUCTURED_EXPLANATION_STOPS,
    build_explanation_response_format,
    parse_structured_explanation,
    render_policy_explanation_structured,
    resolve_structured_explanation_citation,
)
from codegraph.llm.tasks.explanation import build_explanation_evidence, build_explanation_prompt

ExplanationParseMode = Literal["strict", "salvage"]


def _read_code_snippet(file_path: str, needle: str, before: int = 8, after: int = 24) -> str:
    return extract_code_snippet(file_path, needle, before=before, after=after)


def _build_prompt(violation: dict[str, Any], code_snippet: str) -> list[dict[str, str]]:
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


def _call_llm(messages: list[dict[str, str]], model: str) -> str:
    return generate_chat_completion(messages, model=model, task_type="explanation")


def _method_name_from_signature(signature: Any) -> str:
    if not isinstance(signature, str):
        return ""
    text = signature.strip()
    if not text:
        return ""
    return text.split(".")[-1].split("(")[0]


def _allow_salvage(parse_mode: ExplanationParseMode) -> bool:
    if parse_mode == "strict":
        return False
    if parse_mode == "salvage":
        return True
    raise ValueError(f"Unsupported explanation parse mode: {parse_mode}")


def _parse_or_raise(
    response: str,
    *,
    evidence_cards: list[dict[str, Any]],
    parse_mode: ExplanationParseMode,
) -> dict[str, str]:
    parsed = parse_structured_explanation(response, allow_salvage=_allow_salvage(parse_mode))
    if parsed is None:
        raise ValueError("LLM returned an invalid structured explanation payload.")
    return resolve_structured_explanation_citation(
        parsed,
        evidence_cards=evidence_cards,
    )


def _explain_single_violation(violation: dict[str, Any], *, model: str) -> dict[str, Any]:
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
    violations: list[dict[str, Any]],
    *,
    max_items: int = 10,
    model: str = settings.llm_model,
) -> list[dict[str, Any]]:
    subset = violations[:max_items]
    results: list[dict[str, Any]] = [None] * len(subset)  # type: ignore[list-item]
    with ThreadPoolExecutor(max_workers=max(1, settings.llm_concurrency)) as pool:
        future_to_idx = {pool.submit(_explain_single_violation, v, model=model or settings.llm_model): i for i, v in enumerate(subset)}
        for future in as_completed(future_to_idx):
            idx = future_to_idx[future]
            results[idx] = future.result()
    return results


def generate_policy_explanation(
    violation: dict[str, Any],
    *,
    include_graph_context: bool = True,
    evidence_mode: str = "full",
    structured_output: bool = False,
    model: str = settings.llm_model,
    max_tokens: int | None = None,
    raise_on_error: bool = False,
    parse_mode: ExplanationParseMode = "salvage",
    llm_client=generate_chat_completion,
) -> str:
    evidence_payload = build_explanation_evidence(
        violation,
        include_graph_context=include_graph_context,
        evidence_mode=evidence_mode,
    )
    messages = build_explanation_prompt(
        violation,
        include_graph_context=include_graph_context,
        evidence_mode=evidence_mode,
        structured_output=structured_output,
    )
    response = llm_client(
        messages,
        model=model or settings.llm_model,
        max_tokens=max_tokens,
        stop=STRUCTURED_EXPLANATION_STOPS if structured_output else None,
        response_format=(
            build_explanation_response_format(evidence_cards=evidence_payload.get("evidence_cards"))
            if structured_output
            else None
        ),
        raise_on_error=raise_on_error,
        task_type="explanation",
    )
    if not structured_output:
        return response
    resolved = _parse_or_raise(
        response,
        evidence_cards=evidence_payload.get("evidence_cards") or [],
        parse_mode=parse_mode,
    )
    return render_policy_explanation_structured(resolved)


def generate_policy_explanation_structured(
    violation: dict[str, Any],
    *,
    include_graph_context: bool = True,
    evidence_mode: str = "full",
    model: str = settings.llm_model,
    max_tokens: int | None = None,
    raise_on_error: bool = False,
    parse_mode: ExplanationParseMode = "salvage",
    llm_client=generate_chat_completion,
) -> dict[str, str]:
    evidence_payload = build_explanation_evidence(
        violation,
        include_graph_context=include_graph_context,
        evidence_mode=evidence_mode,
    )
    messages = build_explanation_prompt(
        violation,
        include_graph_context=include_graph_context,
        evidence_mode=evidence_mode,
        structured_output=True,
    )
    response = llm_client(
        messages,
        model=model or settings.llm_model,
        max_tokens=max_tokens,
        stop=STRUCTURED_EXPLANATION_STOPS,
        response_format=build_explanation_response_format(evidence_cards=evidence_payload.get("evidence_cards")),
        raise_on_error=raise_on_error,
        task_type="explanation",
    )
    return _parse_or_raise(
        response,
        evidence_cards=evidence_payload.get("evidence_cards") or [],
        parse_mode=parse_mode,
    )
