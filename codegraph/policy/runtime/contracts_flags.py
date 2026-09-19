from __future__ import annotations

from collections.abc import Sequence
from typing import Any

ANALYSIS_FLAG_NAMES: tuple[str, ...] = (
    "md5_literal",
    "md5_variable",
    "md5_detected",
    "weak_hash_literal",
    "weak_hash_variable",
    "weak_hash_detected",
    "weak_cipher_literal",
    "weak_cipher_detected",
    "insecure_random_detected",
    "sha1prng_detected",
    "path_traversal_detected",
    "path_safe_constant_detected",
    "path_sink_uses_tainted_input",
    "path_sink_uses_safe_constant",
    "path_sink_uses_safe_resource_helper",
    "command_exec_string_tainted",
    "command_exec_args_tainted",
    "command_env_only_tainted",
    "command_injection_detected",
    "ldap_injection_detected",
    "ldap_filter_uses_tainted_input",
    "ldap_filter_uses_safe_constant",
    "xpath_injection_detected",
    "xpath_query_uses_tainted_input",
    "xpath_query_uses_safe_constant",
    "sql_query_uses_tainted_input",
    "sql_query_uses_safe_constant",
    "sql_prepare_call_detected",
    "sql_callable_statement_detected",
    "sql_dynamic_query_detected",
)

HELPER_SUMMARY_LIST_FIELDS: tuple[str, ...] = (
    "safe_constant_return_vars",
    "tainted_return_vars",
)

HELPER_SUMMARY_BOOLEAN_FIELDS: tuple[str, ...] = (
    "safe_constant_return_used_in_path_sink",
    "tainted_return_used_in_path_sink",
    "safe_constant_return_used_in_ldap_filter",
    "tainted_return_used_in_ldap_filter",
    "safe_constant_return_used_in_xpath_query",
    "safe_constant_return_used_in_sql_query",
    "safe_constant_return_used_in_command_sink",
    "tainted_return_used_in_xpath_query",
    "tainted_return_used_in_sql_query",
    "tainted_return_used_in_command_sink",
)

HELPER_SUMMARY_INT_FIELDS: tuple[str, ...] = ("analyzed_call_count",)

EVIDENCE_FIELD_ALIAS_MAP: dict[str, str] = {
    "signature": "target_method",
    "annotations": "graph_context.annotations",
    "called_signatures": "graph_context.calls",
    "file_path": "file_path",
    "modifiers": "modifiers",
    "source_code": "source_code",
    "analysis_flags": "analysis_flags",
}


def _is_sequence_but_not_string(value: Any) -> bool:
    return isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray))


def _normalize_string_list(value: Any, *, field_name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not _is_sequence_but_not_string(value):
        raise TypeError(f"{field_name} must be a sequence of strings")
    normalized: list[str] = []
    for item in value:
        if item is None:
            continue
        normalized.append(str(item))
    return tuple(normalized)


def _normalize_optional_string(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return str(value)


def _normalize_optional_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise TypeError("line numbers must be integers, not booleans")
    if isinstance(value, int):
        return value
    raise TypeError("line numbers must be integers")


def _empty_analysis_flags_dict() -> dict[str, bool]:
    return {name: False for name in ANALYSIS_FLAG_NAMES}
