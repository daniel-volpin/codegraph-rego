from __future__ import annotations

import json
from typing import Any

from codegraph.llm.evidence_cards import resolve_evidence_card

STRUCTURED_EXPLANATION_STOPS = ["<|im_end|>", "<|endoftext|>"]
STRUCTURED_EXPLANATION_FIELDS = ("citation", "why", "fix")
STRUCTURED_EXPLANATION_FIELDS_WITH_EVIDENCE = ("evidence_id", "why", "fix")


def strip_structured_stop_tokens(content: str) -> str:
    text = (content or "").strip()
    for token in STRUCTURED_EXPLANATION_STOPS:
        text = text.replace(token, "")
    return text.strip()


def _extract_json_object(text: str) -> str | None:
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


def _normalize_structured_explanation(payload: Any) -> dict[str, str] | None:
    if not isinstance(payload, dict):
        return None
    if frozenset(payload.keys()) not in {
        frozenset(STRUCTURED_EXPLANATION_FIELDS),
        frozenset(STRUCTURED_EXPLANATION_FIELDS_WITH_EVIDENCE),
    }:
        return None
    expected_fields = (
        STRUCTURED_EXPLANATION_FIELDS_WITH_EVIDENCE if "evidence_id" in payload else STRUCTURED_EXPLANATION_FIELDS
    )
    parsed: dict[str, str] = {}
    for field in expected_fields:
        value = payload.get(field)
        if not isinstance(value, str):
            return None
        normalized = value.strip()
        if not normalized:
            return None
        parsed[field] = normalized
    return parsed


def parse_structured_explanation_strict(content: str) -> dict[str, str] | None:
    text = strip_structured_stop_tokens(content)
    if not text:
        return None
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    return _normalize_structured_explanation(payload)


def salvage_structured_explanation(content: str) -> dict[str, str] | None:
    text = strip_structured_stop_tokens(content)
    if not text:
        return None

    json_text = _extract_json_object(text)
    if json_text:
        try:
            payload = json.loads(json_text)
        except json.JSONDecodeError:
            payload = None
        normalized = _normalize_structured_explanation(payload)
        if normalized is not None:
            return normalized

    lowered = text.lower()
    evidence_idx = lowered.find("evidence_id:")
    citation_idx = lowered.find("citation:")
    why_idx = lowered.find("why:")
    fix_idx = lowered.find("fix:")
    if evidence_idx != -1 and why_idx != -1 and fix_idx != -1 and evidence_idx < why_idx < fix_idx:
        evidence_id = text[evidence_idx + len("evidence_id:") : why_idx].strip()
        why = text[why_idx + len("why:") : fix_idx].strip()
        fix = text[fix_idx + len("fix:") :].strip()
        if evidence_id and why and fix:
            return {"evidence_id": evidence_id, "why": why, "fix": fix}

    if citation_idx != -1 and why_idx != -1 and fix_idx != -1 and citation_idx < why_idx < fix_idx:
        citation = text[citation_idx + len("citation:") : why_idx].strip()
        why = text[why_idx + len("why:") : fix_idx].strip()
        fix = text[fix_idx + len("fix:") :].strip()
        if citation and why and fix:
            return {"citation": citation, "why": why, "fix": fix}
    return None


def parse_structured_explanation(content: str, *, allow_salvage: bool) -> dict[str, str] | None:
    parsed = parse_structured_explanation_strict(content)
    if parsed is not None or not allow_salvage:
        return parsed
    return salvage_structured_explanation(content)


def resolve_structured_explanation_citation(
    parsed: dict[str, str],
    *,
    evidence_cards: list[dict[str, Any]],
) -> dict[str, str]:
    citation = parsed.get("citation")
    evidence_id = parsed.get("evidence_id")
    if evidence_id:
        card = resolve_evidence_card(evidence_cards, evidence_id)
        if card is None:
            raise ValueError("LLM returned an unknown evidence_id.")
        citation = card["citation"]
    if not citation:
        raise ValueError("LLM returned an invalid structured explanation payload.")
    result = {
        "citation": citation,
        "why": parsed["why"],
        "fix": parsed["fix"],
    }
    if evidence_id:
        result["evidence_id"] = evidence_id
    return result


def render_policy_explanation_structured(payload: dict[str, str]) -> str:
    return "\n".join(
        [
            f"Citation: {payload['citation']}",
            f"Why: {payload['why']}",
            f"Fix: {payload['fix']}",
        ]
    )


def build_explanation_response_format(*, evidence_cards: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    use_evidence_cards = bool(evidence_cards)
    if use_evidence_cards:
        properties: dict[str, Any] = {
            "evidence_id": {
                "type": "string",
                "enum": [str(card["id"]) for card in evidence_cards or []],
                "description": "Choose exactly one evidence card id from the provided bundle.",
            },
            "why": {
                "type": "string",
                "description": "One concise sentence explaining why the finding matters.",
            },
            "fix": {
                "type": "string",
                "description": "One concise sentence describing the concrete remediation.",
            },
        }
        required = ["evidence_id", "why", "fix"]
    else:
        properties = {
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
        }
        required = ["citation", "why", "fix"]
    return {
        "type": "json_schema",
        "json_schema": {
            "name": "policy_explanation",
            "strict": True,
            "schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": properties,
                "required": required,
            },
        },
    }
