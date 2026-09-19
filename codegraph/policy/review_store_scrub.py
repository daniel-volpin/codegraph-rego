from __future__ import annotations

import json
from typing import Any

MAX_RECORD_BYTES = 200_000
MAX_STRING_CHARS = 20_000
MAX_NOTES_CHARS = 4_000
MAX_SOURCE_CODE_CHARS = 30_000
MAX_LIST_ITEMS = 200
MAX_DICT_KEYS = 500


def string_cap_for_path(path: str) -> int:
    if path.endswith(".notes"):
        return MAX_NOTES_CHARS
    if path.endswith(".violation.evidence.source_code"):
        return MAX_SOURCE_CODE_CHARS
    return MAX_STRING_CHARS


def scrub_value(value: Any, *, path: str) -> tuple[Any, list[str]]:
    warnings: list[str] = []

    if isinstance(value, str):
        cap = string_cap_for_path(path)
        if len(value) > cap:
            warnings.append(f"truncated_string:{path}")
            return value[:cap], warnings
        return value, warnings

    if isinstance(value, list):
        if len(value) > MAX_LIST_ITEMS:
            warnings.append(f"truncated_list:{path}")
            value = value[:MAX_LIST_ITEMS]
        out: list[Any] = []
        for idx, item in enumerate(value):
            scrubbed, child_warnings = scrub_value(item, path=f"{path}[{idx}]")
            out.append(scrubbed)
            warnings.extend(child_warnings)
        return out, warnings

    if isinstance(value, dict):
        keys = sorted(value.keys(), key=lambda x: str(x))
        if len(keys) > MAX_DICT_KEYS:
            warnings.append(f"truncated_dict:{path}")
            keys = keys[:MAX_DICT_KEYS]
        out: dict[str, Any] = {}
        for key in keys:
            k = str(key)
            scrubbed, child_warnings = scrub_value(value.get(key), path=f"{path}.{k}")
            out[k] = scrubbed
            warnings.extend(child_warnings)
        return out, warnings

    return value, warnings


def json_size_bytes(obj: Any) -> int:
    payload = json.dumps(obj, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return len(payload.encode("utf-8"))


def drop_ladder(record: dict[str, Any], warnings: list[str]) -> tuple[dict[str, Any] | None, list[str]]:
    def current_size() -> int:
        return json_size_bytes(record)

    def pop_path() -> Any:
        return record.get("violation") if isinstance(record.get("violation"), dict) else None

    if current_size() <= MAX_RECORD_BYTES:
        return record, warnings

    violation = pop_path()
    if isinstance(violation, dict):
        evidence = violation.get("evidence") if isinstance(violation.get("evidence"), dict) else None
        if isinstance(evidence, dict) and "vector_context" in evidence:
            evidence.pop("vector_context", None)
            warnings.append("drop_ladder:dropped_violation.evidence.vector_context")
            if current_size() <= MAX_RECORD_BYTES:
                return record, warnings

        gc = (
            evidence.get("graph_context")
            if isinstance(evidence, dict) and isinstance(evidence.get("graph_context"), dict)
            else None
        )
        if isinstance(gc, dict):
            for k in ("calls", "callers", "uses_fields"):
                if k in gc:
                    gc.pop(k, None)
            warnings.append("drop_ladder:reduced_violation.evidence.graph_context")
            if current_size() <= MAX_RECORD_BYTES:
                return record, warnings

        if isinstance(evidence, dict) and "source_code" in evidence:
            evidence.pop("source_code", None)
            warnings.append("drop_ladder:dropped_violation.evidence.source_code")
            if current_size() <= MAX_RECORD_BYTES:
                return record, warnings

        if "evidence" in violation:
            violation.pop("evidence", None)
            warnings.append("drop_ladder:dropped_violation.evidence")
            if current_size() <= MAX_RECORD_BYTES:
                return record, warnings

    llm = record.get("llm")
    if isinstance(llm, dict) and isinstance(llm.get("explanation"), str):
        if len(llm["explanation"]) > 5000:
            llm["explanation"] = llm["explanation"][:5000]
            warnings.append("drop_ladder:truncated_llm.explanation_5000")
            if current_size() <= MAX_RECORD_BYTES:
                return record, warnings

    remediation = record.get("remediation")
    if isinstance(remediation, dict) and "preview" in remediation:
        remediation.pop("preview", None)
        warnings.append("drop_ladder:dropped_remediation.preview")
        if current_size() <= MAX_RECORD_BYTES:
            return record, warnings
    if isinstance(remediation, dict) and "apply" in remediation:
        remediation.pop("apply", None)
        warnings.append("drop_ladder:dropped_remediation.apply")
        if current_size() <= MAX_RECORD_BYTES:
            return record, warnings

    if current_size() > MAX_RECORD_BYTES:
        return None, warnings
    return record, warnings
