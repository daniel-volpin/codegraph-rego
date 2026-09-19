from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from codegraph.policy.runtime.contracts_flags import (
    ANALYSIS_FLAG_NAMES,
    HELPER_SUMMARY_LIST_FIELDS,
    _empty_analysis_flags_dict,
    _is_sequence_but_not_string,
    _normalize_optional_string,
    _normalize_string_list,
)


@dataclass(frozen=True)
class PolicyFieldUse:
    name: str
    type: str | None = None
    class_fqn: str | None = None

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> PolicyFieldUse:
        name = raw.get("name")
        if not isinstance(name, str) or not name.strip():
            raise TypeError("graph_context.uses_fields entries must include a non-blank string name")
        return cls(
            name=name,
            type=_normalize_optional_string(raw.get("type")),
            class_fqn=_normalize_optional_string(raw.get("class_fqn")),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "type": self.type,
            "class_fqn": self.class_fqn,
        }


@dataclass(frozen=True)
class PolicyGraphContext:
    annotations: tuple[str, ...] = ()
    uses_fields: tuple[PolicyFieldUse, ...] = ()
    calls: tuple[str, ...] = ()
    callers: tuple[str, ...] = ()

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> PolicyGraphContext:
        raw_uses_fields = raw.get("uses_fields", [])
        if raw_uses_fields is None:
            raw_uses_fields = []
        if not _is_sequence_but_not_string(raw_uses_fields):
            raise TypeError("graph_context.uses_fields must be a sequence")
        uses_fields: list[PolicyFieldUse] = []
        for item in raw_uses_fields:
            if not isinstance(item, Mapping):
                raise TypeError("graph_context.uses_fields entries must be mappings")
            uses_fields.append(PolicyFieldUse.from_mapping(item))
        return cls(
            annotations=_normalize_string_list(raw.get("annotations", []), field_name="graph_context.annotations"),
            uses_fields=tuple(uses_fields),
            calls=_normalize_string_list(raw.get("calls", []), field_name="graph_context.calls"),
            callers=_normalize_string_list(raw.get("callers", []), field_name="graph_context.callers"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "annotations": list(self.annotations),
            "uses_fields": [item.to_dict() for item in self.uses_fields],
            "calls": list(self.calls),
            "callers": list(self.callers),
        }


@dataclass(frozen=True)
class PolicyAnalysisFlags:
    values: dict[str, bool] = field(default_factory=_empty_analysis_flags_dict)

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> PolicyAnalysisFlags:
        values = _empty_analysis_flags_dict()
        for key in ANALYSIS_FLAG_NAMES:
            value = raw.get(key, values[key])
            values[key] = bool(value)
        return cls(values=values)

    @classmethod
    def empty(cls) -> PolicyAnalysisFlags:
        return cls(values=_empty_analysis_flags_dict())

    def to_dict(self) -> dict[str, bool]:
        return {key: self.values[key] for key in ANALYSIS_FLAG_NAMES}


@dataclass(frozen=True)
class PolicyHelperSummaries:
    safe_constant_return_vars: tuple[str, ...] = ()
    tainted_return_vars: tuple[str, ...] = ()
    safe_constant_return_used_in_path_sink: bool = False
    tainted_return_used_in_path_sink: bool = False
    safe_constant_return_used_in_ldap_filter: bool = False
    tainted_return_used_in_ldap_filter: bool = False
    safe_constant_return_used_in_xpath_query: bool = False
    safe_constant_return_used_in_sql_query: bool = False
    safe_constant_return_used_in_command_sink: bool = False
    tainted_return_used_in_xpath_query: bool = False
    tainted_return_used_in_sql_query: bool = False
    tainted_return_used_in_command_sink: bool = False
    analyzed_call_count: int = 0

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> PolicyHelperSummaries:
        list_values: dict[str, tuple[str, ...]] = {}
        for field_name in HELPER_SUMMARY_LIST_FIELDS:
            list_values[field_name] = _normalize_string_list(raw.get(field_name, []), field_name=field_name)
        int_value = raw.get("analyzed_call_count", 0)
        if isinstance(int_value, bool):
            raise TypeError("helper_summaries.analyzed_call_count must be an integer")
        if int_value is None:
            analyzed_call_count = 0
        elif isinstance(int_value, int):
            analyzed_call_count = int_value
        else:
            raise TypeError("helper_summaries.analyzed_call_count must be an integer")
        return cls(
            safe_constant_return_vars=list_values["safe_constant_return_vars"],
            tainted_return_vars=list_values["tainted_return_vars"],
            safe_constant_return_used_in_path_sink=bool(raw.get("safe_constant_return_used_in_path_sink", False)),
            tainted_return_used_in_path_sink=bool(raw.get("tainted_return_used_in_path_sink", False)),
            safe_constant_return_used_in_ldap_filter=bool(raw.get("safe_constant_return_used_in_ldap_filter", False)),
            tainted_return_used_in_ldap_filter=bool(raw.get("tainted_return_used_in_ldap_filter", False)),
            safe_constant_return_used_in_xpath_query=bool(raw.get("safe_constant_return_used_in_xpath_query", False)),
            safe_constant_return_used_in_sql_query=bool(raw.get("safe_constant_return_used_in_sql_query", False)),
            safe_constant_return_used_in_command_sink=bool(raw.get("safe_constant_return_used_in_command_sink", False)),
            tainted_return_used_in_xpath_query=bool(raw.get("tainted_return_used_in_xpath_query", False)),
            tainted_return_used_in_sql_query=bool(raw.get("tainted_return_used_in_sql_query", False)),
            tainted_return_used_in_command_sink=bool(raw.get("tainted_return_used_in_command_sink", False)),
            analyzed_call_count=analyzed_call_count,
        )

    @classmethod
    def empty(cls) -> PolicyHelperSummaries:
        return cls()

    def to_dict(self) -> dict[str, Any]:
        return {
            "safe_constant_return_vars": list(self.safe_constant_return_vars),
            "tainted_return_vars": list(self.tainted_return_vars),
            "safe_constant_return_used_in_path_sink": self.safe_constant_return_used_in_path_sink,
            "tainted_return_used_in_path_sink": self.tainted_return_used_in_path_sink,
            "safe_constant_return_used_in_ldap_filter": self.safe_constant_return_used_in_ldap_filter,
            "tainted_return_used_in_ldap_filter": self.tainted_return_used_in_ldap_filter,
            "safe_constant_return_used_in_xpath_query": self.safe_constant_return_used_in_xpath_query,
            "safe_constant_return_used_in_sql_query": self.safe_constant_return_used_in_sql_query,
            "safe_constant_return_used_in_command_sink": self.safe_constant_return_used_in_command_sink,
            "tainted_return_used_in_xpath_query": self.tainted_return_used_in_xpath_query,
            "tainted_return_used_in_sql_query": self.tainted_return_used_in_sql_query,
            "tainted_return_used_in_command_sink": self.tainted_return_used_in_command_sink,
            "analyzed_call_count": self.analyzed_call_count,
        }


@dataclass(frozen=True)
class PolicyConfigProperty:
    """A configuration value a method reads, with its declaring location."""

    key: str
    value: str
    source_file: str
    line: int
    ambiguous: bool = False
    conflicting_values: tuple[str, ...] = ()

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> PolicyConfigProperty:
        for required in ("key", "value", "source_file"):
            if not isinstance(raw.get(required), str):
                raise TypeError(f"config_context.resolved entries require a string {required}")
        return cls(
            key=raw["key"],
            value=raw["value"],
            source_file=raw["source_file"],
            line=int(raw.get("line") or 0),
            ambiguous=bool(raw.get("ambiguous")),
            conflicting_values=_normalize_string_list(
                raw.get("conflicting_values", []), field_name="config_context.conflicting_values"
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "value": self.value,
            "source_file": self.source_file,
            "line": self.line,
            "ambiguous": self.ambiguous,
            "conflicting_values": list(self.conflicting_values),
        }


@dataclass(frozen=True)
class PolicyConfigContext:
    resolved: tuple[PolicyConfigProperty, ...] = ()

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> PolicyConfigContext:
        entries = raw.get("resolved", [])
        if entries is None:
            entries = []
        if not _is_sequence_but_not_string(entries):
            raise TypeError("config_context.resolved must be a sequence")
        for item in entries:
            if not isinstance(item, Mapping):
                raise TypeError("config_context.resolved entries must be mappings")
        return cls(resolved=tuple(PolicyConfigProperty.from_mapping(item) for item in entries))

    @classmethod
    def empty(cls) -> PolicyConfigContext:
        return cls()

    def to_dict(self) -> dict[str, Any]:
        return {"resolved": [entry.to_dict() for entry in self.resolved]}
