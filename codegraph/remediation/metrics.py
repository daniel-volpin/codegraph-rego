from __future__ import annotations

import logging
import re
from pathlib import Path

LOGGER = logging.getLogger(__name__)


def extract_testcase_id(value: str | None) -> str:
    match = re.search(r"(BenchmarkTest\d+)", value or "")
    return match.group(1) if match else "unknown"


def capture_raw_llm_output(
    output_dir: str | None,
    testcase_id: str,
    attempt: int,
    content: str,
) -> str | None:
    if not output_dir or not content:
        return None
    safe_testcase = re.sub(r"[^A-Za-z0-9_.-]+", "_", testcase_id or "unknown")
    stable_path = Path(output_dir) / f"raw_llm_{safe_testcase}.txt"
    out_path = Path(output_dir) / f"raw_llm_{safe_testcase}_attempt{attempt}.txt"
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        stable_path.write_text(content, encoding="utf-8")
        out_path.write_text(content, encoding="utf-8")
        return out_path.as_posix()
    except Exception as exc:  # pragma: no cover - filesystem guard
        LOGGER.warning("Failed to capture raw LLM output to %s: %s", out_path, exc)
        return None


def summarize_retry_error(error: str) -> str:
    text = (error or "").strip()
    lowered = text.lower()
    if not text:
        return "generation_error"
    if "edit_span_out_of_bounds" in lowered:
        return "edit_span_out_of_bounds"
    if "edit_original_mismatch" in lowered:
        return "edit_original_mismatch"
    if "edit_spans_overlap" in lowered:
        return "edit_spans_overlap"
    if "invalid_java_syntax" in lowered:
        return "invalid_java_syntax"
    if "method_name_mismatch" in lowered:
        return "method_name_mismatch"
    if "parameter_count_mismatch" in lowered:
        return "parameter_count_mismatch"
    if "plan_invariant_violation" in lowered:
        return text.splitlines()[0][:160]
    if "edits" in lowered:
        return "empty_edits"
    if "valid method replacement" in lowered or "replace method" in lowered or "apply_edits" in lowered:
        return "replacement_not_found"
    if "invalid_method_shape" in lowered:
        return "invalid_method_shape"
    if "access_modifier" in lowered:
        return "missing_access_modifier"
    return text.splitlines()[0][:160]
