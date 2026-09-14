from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from codegraph.java.fragments import (
    JavaFragmentError,
    method_field_use_facts,
    method_invocation_facts,
    parse_source_file,
    require_verified_range,
)
from codegraph.java.models import MethodDeclarationDTO, ParsedJavaFileDTO, SourceRangeDTO, TypeRefDTO


class SnapshotError(ValueError):
    """Base class for source snapshot refusal."""


class AmbiguousMethodError(SnapshotError):
    """Raised when a selector does not uniquely identify one declaration."""


class StaleSourceError(SnapshotError):
    """Raised when the caller's expected source hash does not match."""


class UnsupportedSourceError(SnapshotError):
    """Raised when Java source cannot be parsed by the current parser."""


@dataclass(frozen=True)
class ParameterIdentity:
    type_name: str
    array_dimensions: int = 0
    varargs: bool = False

    @property
    def selector_text(self) -> str:
        suffix = "[]" * self.array_dimensions
        if self.varargs:
            suffix += "..."
        return f"{self.type_name}{suffix}"


@dataclass(frozen=True)
class MethodIdentity:
    workspace_relative_path: str
    declaring_type: str
    name: str
    parameters: tuple[ParameterIdentity, ...]
    is_constructor: bool
    selector: str
    syntactic_signature: str
    source_key: str
    declaration_key: str
    canonical_key: str
    source_sha256: str
    identity_status: Literal["resolved_syntactic", "unresolved_syntactic"]
    resolution_status: str
    resolved_descriptor: str | None = None
    resolved_binding_key: str | None = None


@dataclass(frozen=True)
class SourceSnapshot:
    identity: MethodIdentity
    source_path: str
    workspace_root: str
    full_file_bytes: bytes
    full_file_text: str
    file_sha256: str
    method_sha256: str
    method_source: str
    method_bytes: bytes
    start_byte: int
    end_byte: int
    start_line: int
    end_line: int
    start_column: int
    end_column: int
    newline: str
    annotations: tuple[str, ...] = ()
    modifiers: tuple[str, ...] = ()
    observed_invocations: tuple[dict[str, object], ...] = ()
    observed_field_uses: tuple[dict[str, object], ...] = ()


@dataclass(frozen=True)
class _Selector:
    declaring_type: str
    name: str
    parameters: tuple[ParameterIdentity, ...]
    canonical_key: str | None = None


def sha256_hex(data: bytes | str) -> str:
    payload = data.encode("utf-8") if isinstance(data, str) else data
    return hashlib.sha256(payload).hexdigest()


def _decode_source(source_bytes: bytes) -> str:
    try:
        return source_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise UnsupportedSourceError(f"unsupported_source_encoding: {exc}") from exc


def _workspace_relative_path(workspace_root: str | Path, source_path: str | Path) -> str:
    root = Path(workspace_root).resolve()
    path = Path(source_path).resolve()
    try:
        return path.relative_to(root).as_posix()
    except ValueError as exc:
        raise SnapshotError("source_path_outside_workspace") from exc


def _newline_for(source_bytes: bytes) -> str:
    return "\r\n" if b"\r\n" in source_bytes else "\n"


def _strip_array_suffix(value: str) -> tuple[str, int]:
    text = value.strip()
    dims = 0
    while text.endswith("[]"):
        dims += 1
        text = text[:-2].strip()
    return text, dims


def _type_source_identity(type_ref: TypeRefDTO) -> ParameterIdentity:
    source = type_ref.source or type_ref.qualified_name
    if not source:
        raise UnsupportedSourceError("unsupported_parameter_type: missing_syntax")
    text, suffix_dims = _strip_array_suffix(source)
    if text.endswith("..."):
        text = text[:-3].strip()
    if not text:
        raise UnsupportedSourceError("unsupported_parameter_type: empty")
    dimensions = type_ref.array_dimensions or suffix_dims
    if type_ref.varargs and dimensions > 0:
        dimensions -= 1
    return ParameterIdentity(text, dimensions, bool(type_ref.varargs))


def _parameter_identity_text(text: str) -> ParameterIdentity:
    raw = text.strip()
    varargs = raw.endswith("...")
    if varargs:
        raw = raw[:-3].strip()
    raw, dimensions = _strip_array_suffix(raw)
    if not raw:
        raise SnapshotError("invalid_method_selector")
    return ParameterIdentity(raw, dimensions, varargs)


def _split_selector_parameters(params_text: str) -> tuple[str, ...]:
    parts: list[str] = []
    current: list[str] = []
    generic_depth = 0
    for char in params_text:
        if char == "<":
            generic_depth += 1
        elif char == ">":
            generic_depth -= 1
            if generic_depth < 0:
                raise SnapshotError("invalid_method_selector")
        if char == "," and generic_depth == 0:
            part = "".join(current).strip()
            if part:
                parts.append(part)
            current = []
            continue
        current.append(char)
    if generic_depth != 0:
        raise SnapshotError("invalid_method_selector")
    part = "".join(current).strip()
    if part:
        parts.append(part)
    return tuple(parts)


def parse_method_selector(selector: str) -> _Selector:
    raw = selector.strip()
    if "#file:" in raw:
        canonical = raw.split("#", 1)[1]
        method_name = raw.rsplit("#method:", 1)[-1].split("/", 1)[0]
        if not method_name:
            raise SnapshotError("invalid_method_selector")
        return _Selector(declaring_type="", name=method_name, parameters=(), canonical_key=canonical)
    match = re.fullmatch(r"([^#()]+)#([A-Za-z_$][A-Za-z0-9_$]*)\((.*)\)", raw)
    if not match:
        match = re.fullmatch(r"(.+)\.([A-Za-z_$][A-Za-z0-9_$]*)\((.*)\)", raw)
    if not match:
        raise SnapshotError("invalid_method_selector")
    declaring_type, name, params_text = match.groups()
    parameters = tuple(_parameter_identity_text(part) for part in _split_selector_parameters(params_text)) if params_text.strip() else ()
    return _Selector(declaring_type=declaring_type, name=name, parameters=parameters)


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
