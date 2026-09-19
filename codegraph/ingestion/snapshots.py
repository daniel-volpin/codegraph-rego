from __future__ import annotations

from pathlib import Path

from codegraph.ingestion.snapshot_models import (
    AmbiguousMethodError,
    MethodIdentity,
    ParameterIdentity,
    SnapshotError,
    SourceSnapshot,
    StaleSourceError,
    UnsupportedSourceError,
    _decode_source,
    _newline_for,
    _Selector,
    _type_source_identity,
    _workspace_relative_path,
    parse_method_selector,
    sha256_hex,
)
from codegraph.java.fragments import (
    JavaFragmentError,
    method_field_use_facts,
    method_invocation_facts,
    parse_source_file,
    require_verified_range,
)
from codegraph.java.models import MethodDeclarationDTO, ParsedJavaFileDTO, SourceRangeDTO

__all__ = [
    "AmbiguousMethodError",
    "MethodIdentity",
    "ParameterIdentity",
    "SnapshotError",
    "SourceSnapshot",
    "StaleSourceError",
    "UnsupportedSourceError",
    "_Selector",
    "_column_from_byte",
    "_decode_source",
    "_field_use_facts",
    "_invocation_facts",
    "_method_declaring_type",
    "_method_parameters",
    "_newline_for",
    "_select_method",
    "_selector",
    "_sha256_bytes",
    "_signature",
    "_snapshot_from_parsed",
    "_type_source_identity",
    "_workspace_relative_path",
    "create_source_snapshot",
    "create_source_snapshot_from_bytes",
    "parse_method_selector",
    "sha256_hex",
]

_sha256_bytes = sha256_hex


def _signature(declaring_type: str, name: str, params: tuple[ParameterIdentity, ...]) -> str:
    return f"{declaring_type}.{name}({','.join(param.selector_text for param in params)})"


def _selector(declaring_type: str, name: str, params: tuple[ParameterIdentity, ...]) -> str:
    return f"{declaring_type}#{name}({','.join(param.selector_text for param in params)})"


def _method_parameters(method: MethodDeclarationDTO) -> tuple[ParameterIdentity, ...]:
    return tuple(_type_source_identity(parameter.type) for parameter in method.parameters)


def _method_declaring_type(method: MethodDeclarationDTO) -> str:
    return method.declaring_type_qualified_name or method.declaring_type_source_key


def _select_method(parsed: ParsedJavaFileDTO, selector: _Selector) -> MethodDeclarationDTO:
    candidates = []
    for method in parsed.methods:
        if selector.canonical_key is not None:
            if method.source_key == selector.canonical_key or method.declaration_key == selector.canonical_key:
                candidates.append(method)
            continue
        declaring_type = _method_declaring_type(method)
        if declaring_type != selector.declaring_type or method.name != selector.name:
            continue
        if _method_parameters(method) == selector.parameters:
            candidates.append(method)
    if not candidates and selector.canonical_key is not None and selector.name:
        for method in parsed.methods:
            if method.name == selector.name:
                candidates.append(method)
    if len(candidates) != 1:
        raise AmbiguousMethodError("ambiguous_method_selector" if candidates else "method_selector_not_found")
    return candidates[0]


def _column_from_byte(source_bytes: bytes, offset: int) -> int:
    line_start = source_bytes.rfind(b"\n", 0, offset) + 1
    return len(source_bytes[line_start:offset].decode("utf-8"))


def _invocation_facts(method: MethodDeclarationDTO) -> tuple[dict[str, object], ...]:
    return method_invocation_facts(method)


def _field_use_facts(method: MethodDeclarationDTO) -> tuple[dict[str, object], ...]:
    return method_field_use_facts(method)


def _snapshot_from_parsed(
    *,
    workspace_root: str | Path,
    source_path: str | Path,
    source_bytes: bytes,
    parsed: ParsedJavaFileDTO,
    method: MethodDeclarationDTO,
) -> SourceSnapshot:
    declaration_range: SourceRangeDTO
    try:
        declaration_range = require_verified_range(method.declaration_range, "declaration")
    except JavaFragmentError as exc:
        raise UnsupportedSourceError(str(exc)) from exc
    assert declaration_range.start_byte is not None and declaration_range.end_byte is not None
    method_bytes = source_bytes[declaration_range.start_byte : declaration_range.end_byte]
    method_source = _decode_source(method_bytes)
    declaring_type = _method_declaring_type(method)
    params = _method_parameters(method)
    workspace_relative = _workspace_relative_path(workspace_root, source_path)
    canonical_key = f"{workspace_relative}#{method.source_key}"
    identity = MethodIdentity(
        workspace_relative_path=workspace_relative,
        declaring_type=declaring_type,
        name=method.name,
        parameters=params,
        is_constructor=method.kind in {"constructor", "compact_constructor"},
        selector=_selector(declaring_type, method.name, params),
        syntactic_signature=_signature(declaring_type, method.name, params),
        source_key=method.source_key,
        declaration_key=method.declaration_key,
        canonical_key=canonical_key,
        source_sha256=sha256_hex(source_bytes),
        identity_status="resolved_syntactic" if method.resolution_status == "resolved" else "unresolved_syntactic",
        resolution_status=method.resolution_status,
        resolved_descriptor=method.resolved_descriptor,
        resolved_binding_key=method.resolved_binding_key,
    )
    return SourceSnapshot(
        identity=identity,
        source_path=Path(source_path).as_posix(),
        workspace_root=Path(workspace_root).as_posix(),
        full_file_bytes=source_bytes,
        full_file_text=_decode_source(source_bytes),
        file_sha256=sha256_hex(source_bytes),
        method_sha256=sha256_hex(method_bytes),
        method_source=method_source,
        method_bytes=method_bytes,
        start_byte=declaration_range.start_byte,
        end_byte=declaration_range.end_byte,
        start_line=declaration_range.start_line or 1,
        end_line=declaration_range.end_line or 1,
        start_column=_column_from_byte(source_bytes, declaration_range.start_byte),
        end_column=_column_from_byte(source_bytes, declaration_range.end_byte),
        newline=_newline_for(source_bytes),
        annotations=tuple(method.annotation_names),
        modifiers=tuple(method.modifiers),
        observed_invocations=_invocation_facts(method),
        observed_field_uses=_field_use_facts(method),
    )


def create_source_snapshot_from_bytes(
    *,
    workspace_root: str | Path,
    source_path: str | Path,
    source_bytes: bytes,
    method_selector: str,
    expected_source_sha256: str,
) -> SourceSnapshot:
    file_hash = sha256_hex(source_bytes)
    if not expected_source_sha256 or expected_source_sha256 != file_hash:
        raise StaleSourceError("stale_source_hash")
    _decode_source(source_bytes)
    workspace_relative = _workspace_relative_path(workspace_root, source_path)
    selector = parse_method_selector(method_selector)
    try:
        parsed = parse_source_file(source_bytes, relative_path=workspace_relative, resolve_bindings=True)
        method = _select_method(parsed, selector)
    except JavaFragmentError as exc:
        raise UnsupportedSourceError(str(exc)) from exc
    return _snapshot_from_parsed(
        workspace_root=workspace_root,
        source_path=source_path,
        source_bytes=source_bytes,
        parsed=parsed,
        method=method,
    )


def create_source_snapshot(
    *,
    workspace_root: str | Path,
    source_path: str | Path,
    method_selector: str,
    expected_source_sha256: str,
) -> SourceSnapshot:
    source_bytes = Path(source_path).read_bytes()
    return create_source_snapshot_from_bytes(
        workspace_root=workspace_root,
        source_path=source_path,
        source_bytes=source_bytes,
        method_selector=method_selector,
        expected_source_sha256=expected_source_sha256,
    )
