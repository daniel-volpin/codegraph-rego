from __future__ import annotations

from typing import Any

from pydantic import BaseModel

SUPPORTED_TRACE_PREDICATES = {
    # Weak Hash
    "weak_hash_detected", "calls_md5", "calls_weak_hash",
    "source_md5", "source_weak_hash", "analysis_md5", "analysis_weak_hash",
    # Weak Random
    "insecure_random", "source_insecure_random", "calls_insecure_random",
    "analysis_insecure_random", "random_context",
    # Weak Crypto
    "weak_cipher_detected", "source_weak_cipher", "analysis_weak_cipher",
}


class TraceProfile(BaseModel):
    """Normalized canonical signature abstracting away noisy OPA variables."""

    rule_id: str | None
    is_vulnerable: bool
    detected_via_source: bool
    detected_via_graph: bool
    detected_via_ast: bool


class PolicyStateTrace(BaseModel):
    """Model capturing the boolean predicate states before and after remediation."""

    package_path: str
    rule_id: str | None
    trace_source: str
    before_trace_raw: dict[str, Any] | None = None
    after_trace_raw: dict[str, Any] | None = None
    before_trace_filtered: dict[str, Any] | None = None
    after_trace_filtered: dict[str, Any] | None = None
    before_trace_normalized: TraceProfile | None = None
    after_trace_normalized: TraceProfile | None = None
    trace_fields_used: list[str]


def filter_predicate_trace(raw_trace: dict[str, Any] | None) -> dict[str, Any] | None:
    """Filter a raw package-root evaluation to extract only known boolean predicates."""
    if raw_trace is None:
        return None
    filtered = {}
    for key, val in raw_trace.items():
        if key in SUPPORTED_TRACE_PREDICATES and isinstance(val, bool):
            filtered[key] = val
    return filtered


def project_trace_profile(rule_id: str | None, filtered_trace: dict[str, Any] | None) -> TraceProfile | None:
    """Project loosely coupled rego exports down into an implicit standardized contract."""
    if not filtered_trace or not rule_id:
        return None

    is_vulnerable = False
    detected_via_source = False
    detected_via_graph = False
    detected_via_ast = False

    if rule_id in ("ISO-A.10-WEAK-HASH", "CWE-328"):
        is_vulnerable = filtered_trace.get("weak_hash_detected", False)
        detected_via_source = filtered_trace.get("source_md5", False) or filtered_trace.get("source_weak_hash", False)
        detected_via_graph = filtered_trace.get("calls_md5", False) or filtered_trace.get("calls_weak_hash", False)
        detected_via_ast = filtered_trace.get("analysis_md5", False) or filtered_trace.get("analysis_weak_hash", False)

    elif rule_id in ("ISO-A.10-WEAK-RANDOM", "CWE-330"):
        is_vulnerable = filtered_trace.get("insecure_random", False)
        detected_via_source = filtered_trace.get("source_insecure_random", False)
        detected_via_graph = filtered_trace.get("calls_insecure_random", False)
        detected_via_ast = filtered_trace.get("analysis_insecure_random", False)

    elif rule_id in ("ISO-A.10-WEAK-CRYPTO", "CWE-327"):
        is_vulnerable = filtered_trace.get("weak_cipher_detected", False)
        detected_via_source = filtered_trace.get("source_weak_cipher", False)
        detected_via_ast = filtered_trace.get("analysis_weak_cipher", False)
    else:
        return None

    return TraceProfile(
        rule_id=rule_id,
        is_vulnerable=is_vulnerable,
        detected_via_source=detected_via_source,
        detected_via_graph=detected_via_graph,
        detected_via_ast=detected_via_ast,
    )
