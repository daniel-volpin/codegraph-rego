from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from codegraph.java.models import MethodDeclarationDTO, ParsedJavaFileDTO, SourceRangeDTO
from codegraph.java.service import JavaParserError, parse_java_source


class JavaFragmentError(ValueError):
    """Raised when a Java method fragment cannot be represented safely."""


@dataclass(frozen=True)
class ParsedMethodFragment:
    parsed: ParsedJavaFileDTO
    method: MethodDeclarationDTO
    method_bytes: bytes
    method_source: str


def require_verified_range(source_range: SourceRangeDTO | None, label: str) -> SourceRangeDTO:
    if source_range is None or source_range.status != "verified":
        reason = source_range.reason if source_range is not None else "absent"
        raise JavaFragmentError(f"unverified_{label}_range: {reason}")
    if source_range.start_byte is None or source_range.end_byte is None:
        raise JavaFragmentError(f"unverified_{label}_range")
    return source_range


def parse_strict_method_fragment(
    fragment_bytes: bytes,
    *,
    relative_path: str = "CandidateReplacement.java",
    require_body: bool = True,
) -> ParsedMethodFragment:
    try:
        fragment_text = fragment_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise JavaFragmentError(f"invalid_candidate_encoding: {exc}") from exc
    wrapped = ("class CandidateReplacement {\n" + fragment_text + "\n}\n").encode("utf-8")
    try:
        parsed = parse_java_source(wrapped, relative_path=relative_path, resolve_bindings=False)
        method = parsed.require_exactly_one_root_wrapper_method()
    except (JavaParserError, ValueError) as exc:
        raise JavaFragmentError(f"expected_exactly_one_method_declaration: {exc}") from exc
    if method.kind != "method":
        raise JavaFragmentError("expected_exactly_one_method_declaration")
    if require_body and method.body_range is None:
        raise JavaFragmentError("invalid_method_shape: bodyless_method_unsupported")
    declaration_range = require_verified_range(method.declaration_range, "declaration")
    method_bytes = wrapped[declaration_range.start_byte : declaration_range.end_byte]
    try:
        method_source = method_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise JavaFragmentError(f"invalid_candidate_encoding: {exc}") from exc
    return ParsedMethodFragment(parsed=parsed, method=method, method_bytes=method_bytes, method_source=method_source)


def _without_none(items: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in items.items() if value is not None}


def preview_resolution_status(status: str) -> str:
    return "unresolved" if status == "not_attempted" else status


def invocation_fact(invocation: Any) -> dict[str, Any]:
    status = preview_resolution_status(str(invocation.resolution_status))
    unresolved_reason = invocation.unresolved_reason
    if status == "unresolved" and not unresolved_reason:
        unresolved_reason = "binding_resolution_not_attempted"
    return _without_none(
        {
            "name": invocation.name,
            "qualifier_source": invocation.qualifier_source,
            "argument_count": invocation.argument_count,
            "kind": invocation.kind,
            "terminal_chain_member": invocation.terminal_chain_member,
            "chain_members": tuple(invocation.chain_members),
            "resolution_status": status,
            "resolved_owner": invocation.resolved_owner,
            "resolved_name": invocation.resolved_name,
            "resolved_descriptor": invocation.resolved_descriptor,
            "unresolved_reason": unresolved_reason,
        }
    )


def invocation_call_name(fact: dict[str, Any]) -> str:
    qualifier = fact.get("qualifier_source")
    name = str(fact.get("name") or "")
    if qualifier:
        return f"{qualifier}.{name}"
    return name


def field_use_fact(field: Any) -> dict[str, Any]:
    status = preview_resolution_status(str(field.resolution_status))
    unresolved_reason = field.unresolved_reason
    if status == "unresolved" and not unresolved_reason:
        unresolved_reason = "binding_resolution_not_attempted"
    return _without_none(
        {
            "name": field.name,
            "qualifier_source": field.qualifier_source,
            "type": None,
            "class_fqn": field.declaring_type,
            "declaring_type": field.declaring_type,
            "resolution_status": status,
            "unresolved_reason": unresolved_reason,
        }
    )


def observed_field_uses_from_invocations(method: MethodDeclarationDTO) -> tuple[dict[str, Any], ...]:
    fields: dict[str, dict[str, Any]] = {}
    for invocation in method.invocations:
        qualifier = invocation.qualifier_source or ""
        if qualifier.startswith("this."):
            field_name = qualifier.removeprefix("this.").split(".", 1)[0]
            if field_name:
                fields.setdefault(
                    field_name,
                    {
                        "name": field_name,
                        "type": "Logger" if field_name.lower().startswith("log") else None,
                        "class_fqn": method.declaring_type_qualified_name,
                        "qualifier_source": "this",
                        "resolution_status": "unresolved",
                        "unresolved_reason": "inferred_from_jdt_invocation_qualifier",
                    },
                )
    return tuple(fields.values())


def method_invocation_facts(method: MethodDeclarationDTO) -> tuple[dict[str, Any], ...]:
    return tuple(invocation_fact(invocation) for invocation in method.invocations)


def method_field_use_facts(method: MethodDeclarationDTO) -> tuple[dict[str, Any], ...]:
    by_name: dict[str, dict[str, Any]] = {}
    for field in method.field_uses:
        fact = field_use_fact(field)
        by_name[str(fact["name"])] = fact
    for fact in observed_field_uses_from_invocations(method):
        by_name.setdefault(str(fact["name"]), fact)
    return tuple(by_name.values())


def parse_source_file(
    source_bytes: bytes,
    *,
    relative_path: str,
    source_roots: tuple[Path, ...] = (),
    classpath: tuple[Path, ...] = (),
    resolve_bindings: bool = True,
    language_level: str | None = None,
) -> ParsedJavaFileDTO:
    try:
        parsed = parse_java_source(
            source_bytes,
            relative_path=relative_path,
            source_roots=source_roots,
            classpath=classpath,
            resolve_bindings=resolve_bindings,
            language_level=language_level,
        )
    except JavaParserError as exc:
        raise JavaFragmentError(f"unsupported_source: {exc}") from exc
    failures = [diagnostic.message for diagnostic in parsed.diagnostics if diagnostic.coverage_impact == "file_failed"]
    if failures:
        raise JavaFragmentError(f"unsupported_source: {'; '.join(failures)}")
    return parsed
