from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence


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
    from codegraph.policy.source_analysis_core import PolicyIndicatorAnalyzer

    return PolicyIndicatorAnalyzer.empty_flags()


@dataclass(frozen=True)
class PolicyFieldUse:
    name: str
    type: str | None = None
    class_fqn: str | None = None

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "PolicyFieldUse":
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
    def from_mapping(cls, raw: Mapping[str, Any]) -> "PolicyGraphContext":
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
    def from_mapping(cls, raw: Mapping[str, Any]) -> "PolicyAnalysisFlags":
        values = _empty_analysis_flags_dict()
        for key in ANALYSIS_FLAG_NAMES:
            value = raw.get(key, values[key])
            values[key] = bool(value)
        return cls(values=values)

    @classmethod
    def empty(cls) -> "PolicyAnalysisFlags":
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
    def from_mapping(cls, raw: Mapping[str, Any]) -> "PolicyHelperSummaries":
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
    def empty(cls) -> "PolicyHelperSummaries":
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
class PolicyBundle:
    target_method: str
    method_name: str | None = None
    class_fqn: str | None = None
    file_path: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    modifiers: tuple[str, ...] = ()
    source_code: str = ""
    graph_context: PolicyGraphContext = field(default_factory=PolicyGraphContext)
    vector_context: tuple[str, ...] = ()
    analysis_flags: PolicyAnalysisFlags | None = field(default_factory=PolicyAnalysisFlags.empty)
    helper_summaries: PolicyHelperSummaries = field(default_factory=PolicyHelperSummaries.empty)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_method": self.target_method,
            "method_name": self.method_name,
            "class_fqn": self.class_fqn,
            "file_path": self.file_path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "modifiers": list(self.modifiers),
            "source_code": self.source_code,
            "graph_context": self.graph_context.to_dict(),
            "vector_context": list(self.vector_context),
            "analysis_flags": None if self.analysis_flags is None else self.analysis_flags.to_dict(),
            "helper_summaries": self.helper_summaries.to_dict(),
        }


@dataclass(frozen=True)
class PolicyInputEnvelope:
    bundles: tuple[PolicyBundle, ...]
    rules_catalog: dict[str, Any]
    catalog: tuple[dict[str, Any], ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "bundles": [bundle.to_dict() for bundle in self.bundles],
            "rules_catalog": self.rules_catalog,
            "catalog": [dict(entry) for entry in self.catalog],
        }


def build_policy_bundle(
    *,
    target_method: str,
    method_name: Any = None,
    class_fqn: Any = None,
    file_path: Any = None,
    start_line: Any = None,
    end_line: Any = None,
    modifiers: Any = (),
    source_code: Any = "",
    graph_context: Mapping[str, Any] | PolicyGraphContext | None = None,
    vector_context: Any = (),
    analysis_flags: Mapping[str, Any] | PolicyAnalysisFlags | None = None,
    helper_summaries: Mapping[str, Any] | PolicyHelperSummaries | None = None,
) -> PolicyBundle:
    if not isinstance(target_method, str) or not target_method.strip():
        raise TypeError("target_method must be a non-blank string")
    if graph_context is None:
        normalized_graph_context = PolicyGraphContext()
    elif isinstance(graph_context, PolicyGraphContext):
        normalized_graph_context = graph_context
    elif isinstance(graph_context, Mapping):
        normalized_graph_context = PolicyGraphContext.from_mapping(graph_context)
    else:
        raise TypeError("graph_context must be a mapping")

    if isinstance(analysis_flags, PolicyAnalysisFlags) or analysis_flags is None:
        normalized_analysis_flags = analysis_flags
    elif isinstance(analysis_flags, Mapping):
        normalized_analysis_flags = PolicyAnalysisFlags.from_mapping(analysis_flags)
    else:
        raise TypeError("analysis_flags must be a mapping or None")

    if helper_summaries is None:
        normalized_helper_summaries = PolicyHelperSummaries.empty()
    elif isinstance(helper_summaries, PolicyHelperSummaries):
        normalized_helper_summaries = helper_summaries
    elif isinstance(helper_summaries, Mapping):
        normalized_helper_summaries = PolicyHelperSummaries.from_mapping(helper_summaries)
    else:
        raise TypeError("helper_summaries must be a mapping")

    return PolicyBundle(
        target_method=target_method,
        method_name=_normalize_optional_string(method_name),
        class_fqn=_normalize_optional_string(class_fqn),
        file_path=_normalize_optional_string(file_path),
        start_line=_normalize_optional_int(start_line),
        end_line=_normalize_optional_int(end_line),
        modifiers=_normalize_string_list(modifiers, field_name="modifiers"),
        source_code="" if source_code is None else str(source_code),
        graph_context=normalized_graph_context,
        vector_context=_normalize_string_list(vector_context, field_name="vector_context"),
        analysis_flags=normalized_analysis_flags,
        helper_summaries=normalized_helper_summaries,
    )


def normalize_policy_bundle_mapping(raw: Mapping[str, Any]) -> PolicyBundle:
    if not isinstance(raw, Mapping):
        raise TypeError("bundle must be a mapping")
    graph_context = raw.get("graph_context", {})
    if graph_context is None or not isinstance(graph_context, Mapping):
        raise TypeError("graph_context must be a mapping")
    analysis_flags = raw.get("analysis_flags", _empty_analysis_flags_dict())
    helper_summaries = raw.get("helper_summaries", {})
    if helper_summaries is None or not isinstance(helper_summaries, Mapping):
        raise TypeError("helper_summaries must be a mapping")
    if analysis_flags is not None and not isinstance(analysis_flags, Mapping):
        raise TypeError("analysis_flags must be a mapping or None")
    return build_policy_bundle(
        target_method=raw.get("target_method"),
        method_name=raw.get("method_name"),
        class_fqn=raw.get("class_fqn"),
        file_path=raw.get("file_path"),
        start_line=raw.get("start_line"),
        end_line=raw.get("end_line"),
        modifiers=raw.get("modifiers", []),
        source_code=raw.get("source_code", ""),
        graph_context=graph_context,
        vector_context=raw.get("vector_context", []),
        analysis_flags=analysis_flags,
        helper_summaries=helper_summaries,
    )


def serialize_policy_bundle(bundle: PolicyBundle | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(bundle, PolicyBundle):
        return bundle.to_dict()
    return normalize_policy_bundle_mapping(bundle).to_dict()


def serialize_policy_input_envelope(
    *,
    bundles: Sequence[PolicyBundle | Mapping[str, Any]],
    rules_catalog: Mapping[str, Any],
    catalog: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    envelope = PolicyInputEnvelope(
        bundles=tuple(
            bundle if isinstance(bundle, PolicyBundle) else normalize_policy_bundle_mapping(bundle)
            for bundle in bundles
        ),
        rules_catalog=dict(rules_catalog),
        catalog=tuple(dict(entry) for entry in catalog),
    )
    return envelope.to_dict()
