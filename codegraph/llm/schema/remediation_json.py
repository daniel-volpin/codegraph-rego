from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

from codegraph.remediation.contracts import STRUCTURED_GENERATION_STOPS


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
