from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import javalang
from javalang.tokenizer import LexerError
from javalang.tree import ClassDeclaration, ConstructorDeclaration, InterfaceDeclaration, MethodDeclaration

from codegraph.common.snippet_utils import find_java_block_end_position, find_java_statement_end_position


class SnapshotError(ValueError):
    """Base class for source snapshot refusal."""


class AmbiguousMethodError(SnapshotError):
    """Raised when a selector does not uniquely identify one declaration."""


class StaleSourceError(SnapshotError):
    """Raised when the caller's expected source hash does not match."""


class UnsupportedSourceError(SnapshotError):
    """Raised when Java source cannot be parsed by the current parser."""


class SharedLineReplacementError(SnapshotError):
    """Raised when line-based replacement would affect neighboring code."""


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
    legacy_signature: str
    syntactic_signature: str
    source_sha256: str
    identity_status: Literal["resolved_syntactic", "ambiguous"]


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
    start_line: int
    end_line: int
    start_column: int
    end_column: int
    newline: str
    annotations: tuple[str, ...] = ()
    modifiers: tuple[str, ...] = ()


@dataclass(frozen=True)
class _Selector:
    declaring_type: str
    name: str
    parameters: tuple[ParameterIdentity, ...] | None
    legacy_empty_params: bool


@dataclass(frozen=True)
class _Declaration:
    declaring_type: str
    name: str
    parameters: tuple[ParameterIdentity, ...]
    is_constructor: bool
    start_line: int
    start_column: int
    end_line: int
    end_column: int
    annotations: tuple[str, ...]
    modifiers: tuple[str, ...]

    @property
    def selector(self) -> str:
        params = ",".join(param.selector_text for param in self.parameters)
        return f"{self.declaring_type}#{self.name}({params})"

    @property
    def legacy_signature(self) -> str:
        return f"{self.declaring_type}.{self.name}()"

    @property
    def syntactic_signature(self) -> str:
        params = ",".join(param.selector_text for param in self.parameters)
        return f"{self.declaring_type}.{self.name}({params})"


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


def _line_bytes(source_bytes: bytes) -> list[bytes]:
    return source_bytes.splitlines(keepends=True)


def _newline_for(source_bytes: bytes) -> str:
    return "\r\n" if b"\r\n" in source_bytes else "\n"


def _type_parts_and_dimensions(type_node: Any) -> tuple[tuple[str, ...], int]:
    if type_node is None:
        return (), 0
    parts: list[str] = []
    dimensions = 0
    current = type_node
    while current is not None:
        if getattr(current, "arguments", None):
            raise UnsupportedSourceError("unsupported_parameter_type: generic_type_arguments")
        name = getattr(current, "name", None)
        if not name:
            text = str(current)
            if "." in text:
                parts.extend(part for part in text.split(".") if part)
                break
            if text:
                parts.append(text)
                break
        else:
            parts.append(str(name))
        dimensions += len(getattr(current, "dimensions", None) or [])
        current = getattr(current, "sub_type", None)
    return tuple(parts), dimensions


def _parameter_identity(param: Any) -> ParameterIdentity:
    type_node = getattr(param, "type", None)
    type_parts, array_dimensions = _type_parts_and_dimensions(type_node)
    return ParameterIdentity(
        type_name=".".join(type_parts),
        array_dimensions=array_dimensions,
        varargs=bool(getattr(param, "varargs", False)),
    )


def _annotation_names(node: Any) -> tuple[str, ...]:
    return tuple(
        str(getattr(annotation, "name", "")).split(".")[-1]
        for annotation in (getattr(node, "annotations", None) or [])
        if getattr(annotation, "name", None)
    )


def _modifiers(node: Any) -> tuple[str, ...]:
    return tuple(sorted(str(modifier) for modifier in (getattr(node, "modifiers", None) or []) if modifier))


def _parse_parameter_text(text: str) -> ParameterIdentity:
    raw = text.strip()
    varargs = raw.endswith("...")
    if varargs:
        raw = raw[:-3]
    dimensions = raw.count("[]")
    raw = raw.replace("[]", "").strip()
    if not raw:
        raise SnapshotError("invalid_method_selector")
    return ParameterIdentity(raw, dimensions, varargs)


def parse_method_selector(selector: str) -> _Selector:
    raw = selector.strip()
    match = re.fullmatch(r"(.+?)(?:#|\.)([A-Za-z_$][A-Za-z0-9_$]*)\((.*)\)", raw)
    if not match:
        raise SnapshotError("invalid_method_selector")
    declaring_type, name, params_text = match.groups()
    legacy_empty = "#" not in raw and params_text.strip() == ""
    if legacy_empty:
        parameters = None
    elif params_text.strip():
        parameters = tuple(_parse_parameter_text(part) for part in params_text.split(",") if part.strip())
    else:
        parameters = ()
    return _Selector(declaring_type=declaring_type, name=name, parameters=parameters, legacy_empty_params=legacy_empty)


def _iter_type_declarations(type_decls: Any, package: str, parent_fqn: str | None = None):
    for decl in type_decls or []:
        if not isinstance(decl, (ClassDeclaration, InterfaceDeclaration)):
            continue
        class_name = getattr(decl, "name", "UnknownClass")
        class_fqn = f"{package}.{class_name}" if not parent_fqn else f"{parent_fqn}${class_name}"
        yield decl, class_fqn
        body_types = [
            node for node in getattr(decl, "body", []) if isinstance(node, (ClassDeclaration, InterfaceDeclaration))
        ]
        yield from _iter_type_declarations(body_types, package, class_fqn)


def _collect_declarations(text: str) -> tuple[_Declaration, ...]:
    try:
        tree = javalang.parse.parse(text)
    except (javalang.parser.JavaSyntaxError, LexerError, TypeError, IndexError) as exc:
        raise UnsupportedSourceError(f"unsupported_source: {exc.__class__.__name__}") from exc
    package = getattr(tree, "package", None)
    package_name = package.name if package and hasattr(package, "name") else "unknown"
    lines = text.splitlines()
    declarations: list[_Declaration] = []
    for decl, class_fqn in _iter_type_declarations(getattr(tree, "types", []), package_name):
        for method in getattr(decl, "methods", []) or []:
            if not isinstance(method, MethodDeclaration) or not method.position:
                continue
            start_line = int(method.position.line)
            parser_col = max(0, int(method.position.column) - 1)
            start_col = _declaration_line_start_column(text, start_line, parser_col)
            try:
                if getattr(method, "body", None) is None:
                    end_line, end_col = find_java_statement_end_position(lines, start_line, parser_col)
                else:
                    end_line, end_col = find_java_block_end_position(lines, start_line, parser_col)
            except ValueError as exc:
                raise UnsupportedSourceError(f"unsupported_source: {exc}") from exc
            declarations.append(
                _Declaration(
                    declaring_type=class_fqn,
                    name=method.name,
                    parameters=tuple(_parameter_identity(param) for param in (method.parameters or [])),
                    is_constructor=False,
                    start_line=start_line,
                    start_column=start_col,
                    end_line=end_line,
                    end_column=end_col,
                    annotations=_annotation_names(method),
                    modifiers=_modifiers(method),
                )
            )
        for ctor in getattr(decl, "constructors", []) or []:
            if not isinstance(ctor, ConstructorDeclaration) or not ctor.position:
                continue
            start_line = int(ctor.position.line)
            parser_col = max(0, int(ctor.position.column) - 1)
            start_col = _declaration_line_start_column(text, start_line, parser_col)
            try:
                end_line, end_col = find_java_block_end_position(lines, start_line, parser_col)
            except ValueError as exc:
                raise UnsupportedSourceError(f"unsupported_source: {exc}") from exc
            declarations.append(
                _Declaration(
                    declaring_type=class_fqn,
                    name=getattr(decl, "name", class_fqn.rsplit(".", 1)[-1]),
                    parameters=tuple(_parameter_identity(param) for param in (ctor.parameters or [])),
                    is_constructor=True,
                    start_line=start_line,
                    start_column=start_col,
                    end_line=end_line,
                    end_column=end_col,
                    annotations=_annotation_names(ctor),
                    modifiers=_modifiers(ctor),
                )
            )
    return tuple(declarations)


def _declaration_line_start_column(text: str, start_line: int, parser_column: int) -> int:
    line = text.splitlines()[start_line - 1]
    leading = len(line) - len(line.lstrip())
    prefix = line[leading:parser_column].strip()
    if not prefix or all(part in {"public", "private", "protected", "static", "final", "synchronized"} for part in prefix.split()):
        return leading
    return parser_column


def _select_declaration(declarations: tuple[_Declaration, ...], selector: _Selector) -> _Declaration:
    matches = [
        decl
        for decl in declarations
        if decl.declaring_type == selector.declaring_type
        and decl.name == selector.name
        and (selector.parameters is None or decl.parameters == selector.parameters)
    ]
    if len(matches) != 1:
        raise AmbiguousMethodError("ambiguous_method_selector" if matches else "method_selector_not_found")
    if selector.legacy_empty_params:
        same_name = [
            decl for decl in declarations if decl.declaring_type == selector.declaring_type and decl.name == selector.name
        ]
        if len(same_name) != 1:
            raise AmbiguousMethodError("ambiguous_legacy_method_selector")
    return matches[0]


def _assert_safe_line_bounds(source_bytes: bytes, decl: _Declaration) -> None:
    text = _decode_source(source_bytes)
    lines = text.splitlines(keepends=True)
    start_line = lines[decl.start_line - 1]
    end_line = lines[decl.end_line - 1]
    prefix = start_line[: decl.start_column]
    suffix = end_line[decl.end_column + 1 :]
    if prefix.strip() or suffix.strip():
        raise SharedLineReplacementError("unsafe_shared_line_replacement")


def _method_bytes(source_bytes: bytes, decl: _Declaration) -> bytes:
    lines = _line_bytes(source_bytes)
    return b"".join(lines[decl.start_line - 1 : decl.end_line])


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
    text = _decode_source(source_bytes)
    selector = parse_method_selector(method_selector)
    declarations = _collect_declarations(text)
    declaration = _select_declaration(declarations, selector)
    _assert_safe_line_bounds(source_bytes, declaration)
    method_bytes = _method_bytes(source_bytes, declaration)
    method_source = _decode_source(method_bytes)
    identity = MethodIdentity(
        workspace_relative_path=_workspace_relative_path(workspace_root, source_path),
        declaring_type=declaration.declaring_type,
        name=declaration.name,
        parameters=declaration.parameters,
        is_constructor=declaration.is_constructor,
        selector=declaration.selector,
        legacy_signature=declaration.legacy_signature,
        syntactic_signature=declaration.syntactic_signature,
        source_sha256=file_hash,
        identity_status="resolved_syntactic",
    )
    return SourceSnapshot(
        identity=identity,
        source_path=Path(source_path).as_posix(),
        workspace_root=Path(workspace_root).as_posix(),
        full_file_bytes=source_bytes,
        full_file_text=text,
        file_sha256=file_hash,
        method_sha256=sha256_hex(method_bytes),
        method_source=method_source,
        method_bytes=method_bytes,
        start_line=declaration.start_line,
        end_line=declaration.end_line,
        start_column=declaration.start_column,
        end_column=declaration.end_column,
        newline=_newline_for(source_bytes),
        annotations=declaration.annotations,
        modifiers=declaration.modifiers,
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
