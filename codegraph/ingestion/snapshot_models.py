from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from codegraph.java.models import TypeRefDTO


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
