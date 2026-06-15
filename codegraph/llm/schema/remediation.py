from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

from codegraph.remediation.contracts import STRUCTURED_GENERATION_FIELDS, STRUCTURED_GENERATION_STOPS
from codegraph.remediation.editing import apply_method_edits
from codegraph.remediation.planning import validate_remediation_plan


def extract_json_block(text: str) -> str | None:
    if not text:
        return None
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    return text[start : end + 1]


def extract_assistant_content(response: Any) -> str:
    if isinstance(response, str):
        return response
    if isinstance(response, dict):
        try:
            choices = response.get("choices") or []
            if choices and isinstance(choices[0], dict):
                message = choices[0].get("message") or {}
                content = message.get("content")
                if isinstance(content, str):
                    return content
        except Exception:  # pragma: no cover - defensive guard
            pass
    return str(response or "")


def strip_structured_stop_tokens(text: str) -> str:
    raw = (text or "").strip()
    for token in STRUCTURED_GENERATION_STOPS:
        raw = raw.replace(token, "")
    return raw.strip()


def normalize_generated_lines(lines: Iterable[str]) -> list[str]:
    normalized_lines: list[str] = []
    for raw_line in lines:
        line = str(raw_line)
        line = line.replace("\r\n", "\n").replace("\r", "\n")
        if "\\n" in line and "\n" not in line:
            line = line.replace("\\n", "\n")
        for split_line in line.split("\n"):
            normalized_lines.append(split_line.rstrip("\r"))
    while normalized_lines and normalized_lines[-1].strip() == "":
        normalized_lines.pop()
    return normalized_lines


def parse_json_object_strict(text: str) -> dict[str, Any] | None:
    raw = text.strip()
    if not raw:
        return None
    try:
        loaded = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return loaded if isinstance(loaded, dict) else None


def salvage_json_object_from_text(text: str) -> dict[str, Any] | None:
    raw = text.strip()
    if not raw:
        return None

    extracted = extract_json_block(raw)
    if extracted:
        try:
            loaded = json.loads(extracted)
            if isinstance(loaded, dict):
                return loaded
        except json.JSONDecodeError:
            pass

    decoder = json.JSONDecoder()
    in_string = False
    quote_char = ""
    escaped = False
    for idx, char in enumerate(raw):
        if in_string:
            if escaped:
                escaped = False
                continue
            if char == "\\":
                escaped = True
                continue
            if char == quote_char:
                in_string = False
            continue

        if char in ('"', "'"):
            in_string = True
            quote_char = char
            continue

        if char != "{":
            continue

        try:
            loaded, _ = decoder.raw_decode(raw[idx:])
        except json.JSONDecodeError:
            continue
        if isinstance(loaded, dict):
            return loaded
    return None


def parse_json_object_from_text(text: str, *, allow_salvage: bool) -> dict[str, Any] | None:
    parsed = parse_json_object_strict(text)
    if parsed is not None or not allow_salvage:
        return parsed
    return salvage_json_object_from_text(text)


def _empty_parse_error(schema_error: str) -> dict[str, Any]:
    return {
        "decision": None,
        "edits": None,
        "replacement_method_lines": None,
        "replacement_method_code": None,
        "reason": None,
        "raw_response_valid": False,
        "schema_error": schema_error,
    }


def _apply_edits_error(schema_error: str, *, edits: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {
        "decision": "apply_edits",
        "edits": edits,
        "replacement_method_lines": None,
        "replacement_method_code": None,
        "reason": "",
        "raw_response_valid": False,
        "schema_error": schema_error,
    }


def _parse_top_level_generation(data: dict[str, Any]) -> tuple[str, list[Any], str] | dict[str, Any]:
    if set(data.keys()) != STRUCTURED_GENERATION_FIELDS:
        return _empty_parse_error("schema_mismatch: expected decision/edits/reason")

    decision = data.get("decision")
    edits = data.get("edits")
    reason = data.get("reason")
    if decision not in {"apply_edits", "no_fix"}:
        return _empty_parse_error("schema_mismatch: invalid_decision")
    if not isinstance(edits, list):
        return _empty_parse_error("schema_mismatch: edits must be array")
    if not isinstance(reason, str):
        return _empty_parse_error("schema_mismatch: reason must be string")
    return decision, edits, reason


def _normalize_edit(edit: Any) -> dict[str, Any] | str:
    if not isinstance(edit, dict):
        return "schema_mismatch: edit must be object"
    required_keys = {"start_line", "end_line", "original_lines", "replacement_lines"}
    if set(edit.keys()) != required_keys:
        return "schema_mismatch: invalid_edit_shape"
    if not isinstance(edit.get("start_line"), int) or not isinstance(edit.get("end_line"), int):
        return "schema_mismatch: edit_line_bounds_must_be_int"

    original_lines = edit.get("original_lines")
    replacement_lines = edit.get("replacement_lines")
    if not isinstance(original_lines, list) or not isinstance(replacement_lines, list):
        return "schema_mismatch: edit_lines_must_be_array"
    if any(not isinstance(line, str) for line in original_lines + replacement_lines):
        return "schema_mismatch: edit_lines_must_contain_strings"
    return {
        "start_line": edit["start_line"],
        "end_line": edit["end_line"],
        "original_lines": normalize_generated_lines(original_lines),
        "replacement_lines": normalize_generated_lines(replacement_lines),
    }


def _normalize_edits(edits: list[Any]) -> list[dict[str, Any]] | str:
    normalized_edits: list[dict[str, Any]] = []
    for edit in edits:
        normalized = _normalize_edit(edit)
        if isinstance(normalized, str):
            return normalized
        normalized_edits.append(normalized)
    return normalized_edits


def _parse_apply_edits_response(
    edits: list[Any],
    *,
    target_method: str | None,
    original_method_lines: list[str] | None,
    plan: Any,
) -> dict[str, Any]:
    if not edits:
        return _apply_edits_error("empty_edits")
    if original_method_lines is None:
        return _apply_edits_error("missing_original_method_context")

    normalized_edits = _normalize_edits(edits)
    if isinstance(normalized_edits, str):
        return _apply_edits_error(normalized_edits)

    try:
        reconstructed_lines, reconstructed_method = apply_method_edits(
            list(original_method_lines),
            normalized_edits,
            str(target_method or ""),
        )
        plan_error = validate_remediation_plan(plan, reconstructed_method)
        if plan_error:
            raise ValueError(plan_error)
    except ValueError as exc:
        return _apply_edits_error(str(exc), edits=normalized_edits)

    return {
        "decision": "apply_edits",
        "edits": normalized_edits,
        "replacement_method_lines": reconstructed_lines,
        "replacement_method_code": reconstructed_method,
        "reason": "",
        "raw_response_valid": True,
        "schema_error": None,
    }


def _parse_no_fix_response(reason: str) -> dict[str, Any]:
    normalized_reason = reason.strip()
    if not normalized_reason:
        return _empty_parse_error("schema_mismatch: no_fix requires reason")
    return {
        "decision": "no_fix",
        "edits": [],
        "replacement_method_lines": None,
        "replacement_method_code": None,
        "reason": normalized_reason,
        "raw_response_valid": True,
        "schema_error": None,
    }


def _parse_structured_generation_response(
    response: Any,
    *,
    target_method: str | None = None,
    original_method_lines: list[str] | None = None,
    plan: Any = None,
    allow_salvage: bool,
) -> dict[str, Any]:
    content = strip_structured_stop_tokens(extract_assistant_content(response))
    data = parse_json_object_from_text(content, allow_salvage=allow_salvage)
    if data is None:
        return _empty_parse_error("invalid_json: malformed remediation generation payload")

    parsed = _parse_top_level_generation(data)
    if isinstance(parsed, dict):
        return parsed

    decision, edits, reason = parsed
    if decision == "apply_edits":
        return _parse_apply_edits_response(
            edits,
            target_method=target_method,
            original_method_lines=original_method_lines,
            plan=plan,
        )
    return _parse_no_fix_response(reason)


def parse_structured_generation_response_strict(
    response: Any,
    *,
    target_method: str | None = None,
    original_method_lines: list[str] | None = None,
    plan: Any = None,
) -> dict[str, Any]:
    return _parse_structured_generation_response(
        response,
        target_method=target_method,
        original_method_lines=original_method_lines,
        plan=plan,
        allow_salvage=False,
    )


def parse_structured_generation_response(
    response: Any,
    *,
    target_method: str | None = None,
    original_method_lines: list[str] | None = None,
    plan: Any = None,
    allow_salvage: bool = True,
) -> dict[str, Any]:
    return _parse_structured_generation_response(
        response,
        target_method=target_method,
        original_method_lines=original_method_lines,
        plan=plan,
        allow_salvage=allow_salvage,
    )


def build_remediation_response_format() -> dict[str, Any]:
    return {
        "type": "json_schema",
        "json_schema": {
            "name": "remediation_generation",
            "strict": True,
            "schema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "decision": {
                        "type": "string",
                        "enum": ["apply_edits", "no_fix"],
                    },
                    "edits": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "additionalProperties": False,
                            "properties": {
                                "start_line": {"type": "integer"},
                                "end_line": {"type": "integer"},
                                "original_lines": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                },
                                "replacement_lines": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                },
                            },
                            "required": [
                                "start_line",
                                "end_line",
                                "original_lines",
                                "replacement_lines",
                            ],
                        },
                    },
                    "reason": {
                        "type": "string",
                    },
                },
                "required": ["decision", "edits", "reason"],
            },
        },
    }
