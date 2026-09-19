from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from codegraph.policy.runtime.contracts_context import (
    PolicyAnalysisFlags,
    PolicyConfigContext,
    PolicyConfigProperty,
    PolicyFieldUse,
    PolicyGraphContext,
    PolicyHelperSummaries,
)
from codegraph.policy.runtime.contracts_flags import (
    ANALYSIS_FLAG_NAMES,
    EVIDENCE_FIELD_ALIAS_MAP,
    HELPER_SUMMARY_BOOLEAN_FIELDS,
    HELPER_SUMMARY_INT_FIELDS,
    HELPER_SUMMARY_LIST_FIELDS,
    _empty_analysis_flags_dict,
    _is_sequence_but_not_string,
    _normalize_optional_int,
    _normalize_optional_string,
    _normalize_string_list,
)

__all__ = [
    "ANALYSIS_FLAG_NAMES",
    "EVIDENCE_FIELD_ALIAS_MAP",
    "HELPER_SUMMARY_BOOLEAN_FIELDS",
    "HELPER_SUMMARY_INT_FIELDS",
    "HELPER_SUMMARY_LIST_FIELDS",
    "PolicyAnalysisFlags",
    "PolicyBundle",
    "PolicyConfigContext",
    "PolicyConfigProperty",
    "PolicyFieldUse",
    "PolicyGraphContext",
    "PolicyHelperSummaries",
    "PolicyInputEnvelope",
    "_empty_analysis_flags_dict",
    "_is_sequence_but_not_string",
    "_normalize_optional_int",
    "_normalize_optional_string",
    "_normalize_string_list",
    "build_policy_bundle",
    "normalize_policy_bundle_mapping",
    "serialize_policy_bundle",
    "serialize_policy_input_envelope",
]


@dataclass(frozen=True)
class PolicyBundle:
    target_method: str
    method_key: str | None = None
    method_name: str | None = None
    class_fqn: str | None = None
    file_path: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    modifiers: tuple[str, ...] = ()
    source_code: str = ""
    source_code_raw: str = ""
    graph_context: PolicyGraphContext = field(default_factory=PolicyGraphContext)
    config_context: PolicyConfigContext = field(default_factory=PolicyConfigContext.empty)
    vector_context: tuple[str, ...] = ()
    analysis_flags: PolicyAnalysisFlags | None = field(default_factory=PolicyAnalysisFlags.empty)
    helper_summaries: PolicyHelperSummaries = field(default_factory=PolicyHelperSummaries.empty)
    workspace_id: str | None = None
    revision_id: str | None = None
    parser: dict[str, Any] | None = None
    taint_paths: tuple[dict[str, Any], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "method_key": self.method_key,
            "target_method": self.target_method,
            "method_name": self.method_name,
            "class_fqn": self.class_fqn,
            "file_path": self.file_path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "modifiers": list(self.modifiers),
            "source_code": self.source_code,
            "source_code_raw": self.source_code_raw,
            "graph_context": self.graph_context.to_dict(),
            "config_context": self.config_context.to_dict(),
            "vector_context": list(self.vector_context),
            "analysis_flags": None if self.analysis_flags is None else self.analysis_flags.to_dict(),
            "helper_summaries": self.helper_summaries.to_dict(),
        }
        if self.workspace_id is not None:
            data["workspace_id"] = self.workspace_id
        if self.revision_id is not None:
            data["revision_id"] = self.revision_id
        if self.parser is not None:
            data["parser"] = self.parser
        if self.taint_paths:
            data["taint_paths"] = list(self.taint_paths)
        return data


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
    method_key: Any = None,
    method_name: Any = None,
    class_fqn: Any = None,
    file_path: Any = None,
    start_line: Any = None,
    end_line: Any = None,
    modifiers: Any = (),
    source_code: Any = "",
    source_code_raw: Any = "",
    graph_context: Mapping[str, Any] | PolicyGraphContext | None = None,
    config_context: Mapping[str, Any] | PolicyConfigContext | None = None,
    vector_context: Any = (),
    analysis_flags: Mapping[str, Any] | PolicyAnalysisFlags | None = None,
    helper_summaries: Mapping[str, Any] | PolicyHelperSummaries | None = None,
    workspace_id: Any = None,
    revision_id: Any = None,
    parser: Any = None,
    taint_paths: Any = (),
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

    if config_context is None:
        normalized_config_context = PolicyConfigContext.empty()
    elif isinstance(config_context, PolicyConfigContext):
        normalized_config_context = config_context
    elif isinstance(config_context, Mapping):
        normalized_config_context = PolicyConfigContext.from_mapping(config_context)
    else:
        raise TypeError("config_context must be a mapping")

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
        method_key=_normalize_optional_string(method_key),
        method_name=_normalize_optional_string(method_name),
        class_fqn=_normalize_optional_string(class_fqn),
        file_path=_normalize_optional_string(file_path),
        start_line=_normalize_optional_int(start_line),
        end_line=_normalize_optional_int(end_line),
        modifiers=_normalize_string_list(modifiers, field_name="modifiers"),
        source_code="" if source_code is None else str(source_code),
        source_code_raw="" if source_code_raw is None else str(source_code_raw),
        graph_context=normalized_graph_context,
        config_context=normalized_config_context,
        vector_context=_normalize_string_list(vector_context, field_name="vector_context"),
        analysis_flags=normalized_analysis_flags,
        helper_summaries=normalized_helper_summaries,
        workspace_id=_normalize_optional_string(workspace_id),
        revision_id=_normalize_optional_string(revision_id),
        parser=dict(parser) if isinstance(parser, Mapping) else None,
        taint_paths=tuple(dict(p) for p in taint_paths if isinstance(p, Mapping)) if isinstance(taint_paths, Sequence) else (),
    )


def normalize_policy_bundle_mapping(raw: Mapping[str, Any]) -> PolicyBundle:
    if not isinstance(raw, Mapping):
        raise TypeError("bundle must be a mapping")
    graph_context = raw.get("graph_context", {})
    if graph_context is None or not isinstance(graph_context, Mapping):
        raise TypeError("graph_context must be a mapping")
    config_context = raw.get("config_context", {})
    if config_context is None or not isinstance(config_context, Mapping):
        raise TypeError("config_context must be a mapping")
    analysis_flags = raw.get("analysis_flags", _empty_analysis_flags_dict())
    helper_summaries = raw.get("helper_summaries", {})
    if helper_summaries is None or not isinstance(helper_summaries, Mapping):
        raise TypeError("helper_summaries must be a mapping")
    if analysis_flags is not None and not isinstance(analysis_flags, Mapping):
        raise TypeError("analysis_flags must be a mapping or None")
    return build_policy_bundle(
        target_method=raw.get("target_method"),
        method_key=raw.get("method_key"),
        method_name=raw.get("method_name"),
        class_fqn=raw.get("class_fqn"),
        file_path=raw.get("file_path"),
        start_line=raw.get("start_line"),
        end_line=raw.get("end_line"),
        modifiers=raw.get("modifiers", []),
        source_code=raw.get("source_code", ""),
        source_code_raw=raw.get("source_code_raw", ""),
        graph_context=graph_context,
        config_context=config_context,
        vector_context=raw.get("vector_context", []),
        analysis_flags=analysis_flags,
        helper_summaries=helper_summaries,
        workspace_id=raw.get("workspace_id"),
        revision_id=raw.get("revision_id"),
        parser=raw.get("parser"),
        taint_paths=raw.get("taint_paths", ()),
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
