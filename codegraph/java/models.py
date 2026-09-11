from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class StrictFrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


CoverageStatus = Literal["complete", "partial", "failed"]
RangeStatus = Literal["verified", "unverified", "absent"]
ResolutionStatus = Literal["resolved", "unresolved", "recovered", "ambiguous", "not_attempted"]
BindingOrigin = Literal["source", "binary", "primitive", "unknown"]
BodyDeclarationKind = Literal[
    "method",
    "constructor",
    "field",
    "initializer",
    "type",
    "enum_constant",
    "annotation_member",
]


class SourceRangeDTO(StrictFrozenModel):
    """Original-source range owned by the adapter.

    Byte offsets are UTF-8 offsets into the exact caller-supplied file bytes,
    start-inclusive and end-exclusive. Line numbers are 1-based display aids.
    """

    start_byte: int | None = Field(default=None, ge=0)
    end_byte: int | None = Field(default=None, ge=0)
    start_line: int | None = Field(default=None, ge=1)
    end_line: int | None = Field(default=None, ge=1)
    start_utf16_offset: int | None = Field(default=None, ge=0)
    end_utf16_offset: int | None = Field(default=None, ge=0)
    status: RangeStatus
    convention: Literal["utf8_byte_start_inclusive_end_exclusive"] = "utf8_byte_start_inclusive_end_exclusive"
    reason: str | None = None

    @model_validator(mode="after")
    def validate_range_consistency(self) -> SourceRangeDTO:
        if self.start_byte is not None and self.end_byte is not None and self.end_byte < self.start_byte:
            raise ValueError("end_byte must be greater than or equal to start_byte")
        if self.start_line is not None and self.end_line is not None and self.end_line < self.start_line:
            raise ValueError("end_line must be greater than or equal to start_line")
        if (
            self.start_utf16_offset is not None
            and self.end_utf16_offset is not None
            and self.end_utf16_offset < self.start_utf16_offset
        ):
            raise ValueError("end_utf16_offset must be greater than or equal to start_utf16_offset")
        if self.status == "verified":
            if self.start_byte is None or self.end_byte is None:
                raise ValueError("verified ranges require byte offsets")
            if self.start_line is None or self.end_line is None:
                raise ValueError("verified ranges require line numbers")
        if self.status in {"unverified", "absent"} and not self.reason:
            raise ValueError(f"{self.status} ranges require a reason")
        return self


class JavaParserProvenanceDTO(StrictFrozenModel):
    backend: Literal["eclipse-jdt"] = "eclipse-jdt"
    backend_version: str
    adapter_version: str
    language_level: str | None = None
    resolution_enabled: bool = False
    classpath_fingerprint: str | None = None


class ImportDTO(StrictFrozenModel):
    name: str
    is_static: bool
    on_demand: bool
    range: SourceRangeDTO


class DiagnosticDTO(StrictFrozenModel):
    severity: Literal["info", "warning", "error"]
    phase: Literal["read", "lex", "parse", "range", "symbol", "adapter"]
    code: str
    message: str
    range: SourceRangeDTO | None = None
    coverage_impact: Literal["none", "file_partial", "file_failed"] = "none"


class TypeRefDTO(StrictFrozenModel):
    source: str | None = None
    qualified_name: str | None = None
    binary_name: str | None = None
    descriptor: str | None = None
    binding_key: str | None = None
    array_dimensions: int = Field(default=0, ge=0)
    varargs: bool = False
    type_arguments: tuple[TypeRefDTO, ...] = ()
    resolution_status: ResolutionStatus
    binding_origin: BindingOrigin = "unknown"
    unresolved_reason: str | None = None

    @model_validator(mode="after")
    def validate_resolution_identity(self) -> TypeRefDTO:
        if self.resolution_status == "resolved" and not (self.binding_key or self.descriptor):
            raise ValueError("resolved types require binding_key or descriptor")
        if self.resolution_status == "resolved" and self.binding_origin not in {"source", "binary", "primitive"}:
            raise ValueError("resolved types require binding_origin source, binary, or primitive")
        if self.resolution_status != "resolved" and self.binding_origin != "unknown":
            raise ValueError("non-resolved types must use unknown binding_origin")
        if self.resolution_status in {"unresolved", "ambiguous", "recovered"} and not self.unresolved_reason:
            raise ValueError(f"{self.resolution_status} types require unresolved_reason")
        return self


class ParameterDTO(StrictFrozenModel):
    name: str
    type: TypeRefDTO
    modifiers: tuple[str, ...] = ()
    range: SourceRangeDTO | None = None


class ArgumentDTO(StrictFrozenModel):
    source: str | None = None
    range: SourceRangeDTO | None = None


class FieldUseDTO(StrictFrozenModel):
    name: str
    range: SourceRangeDTO
    qualifier_source: str | None = None
    declaring_type: str | None = None
    field_binding_key: str | None = None
    resolution_status: ResolutionStatus
    binding_origin: BindingOrigin = "unknown"
    unresolved_reason: str | None = None

    @model_validator(mode="after")
    def validate_resolution_identity(self) -> FieldUseDTO:
        if self.resolution_status == "resolved" and not self.field_binding_key:
            raise ValueError("resolved field uses require field_binding_key")
        if self.resolution_status == "resolved" and self.binding_origin not in {"source", "binary"}:
            raise ValueError("resolved field uses require binding_origin source or binary")
        if self.resolution_status != "resolved" and self.binding_origin != "unknown":
            raise ValueError("non-resolved field uses must use unknown binding_origin")
        if self.resolution_status in {"unresolved", "ambiguous", "recovered"} and not self.unresolved_reason:
            raise ValueError(f"{self.resolution_status} field uses require unresolved_reason")
        return self


class InvocationDTO(StrictFrozenModel):
    source_key: str
    kind: Literal["method", "constructor", "super_constructor", "this_constructor"]
    qualifier_source: str | None = None
    name: str
    argument_count: int = Field(ge=0)
    arguments: tuple[ArgumentDTO, ...] = ()
    invocation_range: SourceRangeDTO
    terminal_chain_member: bool = False
    chain_members: tuple[str, ...] = ()
    resolution_status: ResolutionStatus
    resolved_owner: str | None = None
    resolved_name: str | None = None
    resolved_parameter_types: tuple[TypeRefDTO, ...] = ()
    resolved_return_type: TypeRefDTO | None = None
    resolved_binding_key: str | None = None
    resolved_descriptor: str | None = None
    target_method_source_key: str | None = None
    binding_origin: BindingOrigin = "unknown"
    unresolved_reason: str | None = None

    @model_validator(mode="after")
    def validate_invocation(self) -> InvocationDTO:
        if len(self.arguments) != self.argument_count:
            raise ValueError("argument_count must match arguments length")
        if self.resolution_status == "resolved" and not (self.resolved_binding_key or self.resolved_descriptor):
            raise ValueError("resolved invocations require resolved_binding_key or resolved_descriptor")
        if self.resolution_status == "resolved" and self.binding_origin not in {"source", "binary"}:
            raise ValueError("resolved invocations require binding_origin source or binary")
        if self.resolution_status != "resolved" and self.binding_origin != "unknown":
            raise ValueError("non-resolved invocations must use unknown binding_origin")
        if self.resolution_status in {"unresolved", "ambiguous", "recovered"} and not self.unresolved_reason:
            raise ValueError(f"{self.resolution_status} invocations require unresolved_reason")
        return self


class FieldDeclarationDTO(StrictFrozenModel):
    source_key: str
    declaring_type_source_key: str
    name: str
    type: TypeRefDTO
    modifiers: tuple[str, ...] = ()
    annotation_names: tuple[str, ...] = ()
    declaration_range: SourceRangeDTO
    name_range: SourceRangeDTO | None = None
    initializer_range: SourceRangeDTO | None = None
    has_initializer: bool = False
    binding_key: str | None = None
    resolution_status: ResolutionStatus
    binding_origin: BindingOrigin = "unknown"
    unresolved_reason: str | None = None

    @model_validator(mode="after")
    def validate_field(self) -> FieldDeclarationDTO:
        if self.has_initializer and self.initializer_range is None:
            raise ValueError("fields with initializer require initializer_range")
        if self.resolution_status == "resolved" and not self.binding_key:
            raise ValueError("resolved fields require binding_key")
        if self.resolution_status == "resolved" and self.binding_origin not in {"source", "binary"}:
            raise ValueError("resolved fields require binding_origin source or binary")
        if self.resolution_status != "resolved" and self.binding_origin != "unknown":
            raise ValueError("non-resolved fields must use unknown binding_origin")
        if self.resolution_status in {"unresolved", "ambiguous", "recovered"} and not self.unresolved_reason:
            raise ValueError(f"{self.resolution_status} fields require unresolved_reason")
        return self


class TypeDeclarationDTO(StrictFrozenModel):
    source_key: str
    enclosing_type_source_key: str | None = None
    kind: Literal["class", "interface", "enum", "record", "annotation", "anonymous", "local"]
    name: str
    qualified_name: str | None = None
    binary_name: str | None = None
    nesting_path: tuple[str, ...] = ()
    local_ordinal: int | None = Field(default=None, ge=0)
    body_declaration_kinds: tuple[BodyDeclarationKind, ...] = ()
    modifiers: tuple[str, ...] = ()
    annotation_names: tuple[str, ...] = ()
    superclass: TypeRefDTO | None = None
    interfaces: tuple[TypeRefDTO, ...] = ()
    declaration_range: SourceRangeDTO
    name_range: SourceRangeDTO | None = None
    binding_key: str | None = None
    resolution_status: ResolutionStatus
    binding_origin: BindingOrigin = "unknown"
    unresolved_reason: str | None = None

    @model_validator(mode="after")
    def validate_type_identity(self) -> TypeDeclarationDTO:
        if self.kind in {"anonymous", "local"} and self.local_ordinal is None:
            raise ValueError("local and anonymous types require local_ordinal")
        if self.resolution_status == "resolved" and not self.binding_key:
            raise ValueError("resolved types require binding_key")
        if self.resolution_status == "resolved" and self.binding_origin not in {"source", "binary"}:
            raise ValueError("resolved type declarations require binding_origin source or binary")
        if self.resolution_status != "resolved" and self.binding_origin != "unknown":
            raise ValueError("non-resolved type declarations must use unknown binding_origin")
        if self.resolution_status in {"unresolved", "ambiguous", "recovered"} and not self.unresolved_reason:
            raise ValueError(f"{self.resolution_status} declarations require unresolved_reason")
        return self


class MethodDeclarationDTO(StrictFrozenModel):
    source_key: str
    declaration_key: str
    declaring_type_source_key: str
    declaring_type_qualified_name: str | None = None
    kind: Literal["method", "constructor", "compact_constructor"]
    name: str
    display_signature: str
    full_signature: str
    syntactic_parameter_types: tuple[str, ...] = ()
    modifiers: tuple[str, ...] = ()
    annotation_names: tuple[str, ...] = ()
    return_type: TypeRefDTO | None = None
    parameters: tuple[ParameterDTO, ...] = ()
    thrown_types: tuple[TypeRefDTO, ...] = ()
    declaration_range: SourceRangeDTO
    name_range: SourceRangeDTO | None = None
    body_range: SourceRangeDTO | None = None
    invocations: tuple[InvocationDTO, ...] = ()
    field_uses: tuple[FieldUseDTO, ...] = ()
    resolution_status: ResolutionStatus
    resolved_binding_key: str | None = None
    resolved_descriptor: str | None = None
    binding_origin: BindingOrigin = "unknown"
    unresolved_reason: str | None = None

    @model_validator(mode="after")
    def validate_method(self) -> MethodDeclarationDTO:
        if len(self.syntactic_parameter_types) != len(self.parameters):
            raise ValueError("syntactic_parameter_types must match parameters length")
        if self.kind in {"constructor", "compact_constructor"} and self.return_type is not None:
            raise ValueError("constructors must not declare return_type")
        if self.resolution_status == "resolved" and not (self.resolved_binding_key or self.resolved_descriptor):
            raise ValueError("resolved methods require resolved_binding_key or resolved_descriptor")
        if self.resolution_status == "resolved" and self.binding_origin not in {"source", "binary"}:
            raise ValueError("resolved methods require binding_origin source or binary")
        if self.resolution_status != "resolved" and self.binding_origin != "unknown":
            raise ValueError("non-resolved methods must use unknown binding_origin")
        if self.resolution_status in {"unresolved", "ambiguous", "recovered"} and not self.unresolved_reason:
            raise ValueError(f"{self.resolution_status} methods require unresolved_reason")
        return self


class ParsedJavaFileDTO(StrictFrozenModel):
    schema_version: Literal["codegraph-java/v1"] = "codegraph-java/v1"
    provenance: JavaParserProvenanceDTO
    relative_path: str
    package_name: str | None = None
    imports: tuple[ImportDTO, ...] = ()
    source_sha256: str
    source_byte_length: int = Field(ge=0)
    coverage: CoverageStatus
    diagnostics: tuple[DiagnosticDTO, ...] = ()
    types: tuple[TypeDeclarationDTO, ...] = ()
    fields: tuple[FieldDeclarationDTO, ...] = ()
    methods: tuple[MethodDeclarationDTO, ...] = ()

    @field_validator("source_sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
            raise ValueError("source_sha256 must be 64 lowercase hexadecimal characters")
        return value

    @model_validator(mode="after")
    def validate_coverage(self) -> ParsedJavaFileDTO:
        if self.coverage == "failed" and (self.types or self.fields or self.methods):
            raise ValueError("failed coverage cannot include declarations")
        if self.coverage in {"partial", "failed"} and not self.diagnostics:
            raise ValueError(f"{self.coverage} coverage requires diagnostics")
        if self.coverage == "complete" and any(diagnostic.coverage_impact != "none" for diagnostic in self.diagnostics):
            raise ValueError("complete coverage cannot include coverage-impacting diagnostics")
        self._validate_file_ranges()
        return self

    def _validate_file_ranges(self) -> None:
        verified_ranges: list[SourceRangeDTO] = []

        def collect_range(range_value: SourceRangeDTO | None) -> None:
            if range_value is not None and range_value.status == "verified":
                verified_ranges.append(range_value)

        for import_decl in self.imports:
            collect_range(import_decl.range)
        for type_decl in self.types:
            collect_range(type_decl.declaration_range)
            collect_range(type_decl.name_range)
            _require_contained(type_decl.name_range, type_decl.declaration_range, "type name")
        for field in self.fields:
            collect_range(field.declaration_range)
            collect_range(field.name_range)
            collect_range(field.initializer_range)
            _require_contained(field.name_range, field.declaration_range, "field name")
            _require_contained(field.initializer_range, field.declaration_range, "field initializer")
        for method in self.methods:
            collect_range(method.declaration_range)
            collect_range(method.name_range)
            collect_range(method.body_range)
            _require_contained(method.name_range, method.declaration_range, "method name")
            _require_contained(method.body_range, method.declaration_range, "method body")
            for parameter in method.parameters:
                collect_range(parameter.range)
                _require_contained(parameter.range, method.declaration_range, "parameter")
            invocation_parent = method.body_range or method.declaration_range
            for invocation in method.invocations:
                collect_range(invocation.invocation_range)
                _require_contained(invocation.invocation_range, invocation_parent, "invocation")
                for argument in invocation.arguments:
                    collect_range(argument.range)
                    _require_contained(argument.range, invocation.invocation_range, "argument")
            for field_use in method.field_uses:
                collect_range(field_use.range)
                _require_contained(field_use.range, invocation_parent, "field use")

        for range_value in verified_ranges:
            if range_value.end_byte is not None and range_value.end_byte > self.source_byte_length:
                raise ValueError("verified range exceeds source_byte_length")

        type_ranges = {
            type_decl.source_key: type_decl.declaration_range
            for type_decl in self.types
            if type_decl.declaration_range.status == "verified"
        }
        for field in self.fields:
            _require_contained(field.declaration_range, type_ranges.get(field.declaring_type_source_key), "field")
        for method in self.methods:
            _require_contained(method.declaration_range, type_ranges.get(method.declaring_type_source_key), "method")

    def require_exactly_one_root_wrapper_method(self) -> MethodDeclarationDTO:
        root_types = [type_decl for type_decl in self.types if type_decl.enclosing_type_source_key is None]
        if len(root_types) != 1:
            raise ValueError("expected exactly one root wrapper type")
        wrapper = root_types[0]
        method_member_count = sum(1 for kind in wrapper.body_declaration_kinds if kind in {"method", "constructor"})
        if len(wrapper.body_declaration_kinds) != 1 or method_member_count != 1:
            raise ValueError("expected wrapper direct body to contain exactly one method or constructor")
        direct_methods = [
            method for method in self.methods if method.declaring_type_source_key == wrapper.source_key
        ]
        if len(direct_methods) != 1:
            raise ValueError("expected exactly one method declaration")
        return direct_methods[0]

    def single_method_or_error(self) -> MethodDeclarationDTO:
        if len(self.methods) != 1:
            raise ValueError("expected exactly one method declaration")
        return self.methods[0]


def _require_contained(
    child: SourceRangeDTO | None,
    parent: SourceRangeDTO | None,
    label: str,
) -> None:
    if child is None or parent is None:
        return
    if child.status != "verified" or parent.status != "verified":
        return
    assert child.start_byte is not None
    assert child.end_byte is not None
    assert parent.start_byte is not None
    assert parent.end_byte is not None
    if child.start_byte < parent.start_byte or child.end_byte > parent.end_byte:
        raise ValueError(f"{label} range must be contained by parent range")
