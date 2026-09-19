from __future__ import annotations

from typing import Literal

from pydantic import Field, field_validator, model_validator

from codegraph.java.models_base import (
    ArgumentDTO,
    BindingOrigin,
    BodyDeclarationKind,
    CoverageStatus,
    DiagnosticDTO,
    ImportDTO,
    JavaParserProvenanceDTO,
    ParameterDTO,
    RangeStatus,
    ResolutionStatus,
    SourceRangeDTO,
    StrictFrozenModel,
    TypeRefDTO,
)
from codegraph.java.models_declarations import (
    FieldDeclarationDTO,
    FieldUseDTO,
    InvocationDTO,
    MethodDeclarationDTO,
    TypeDeclarationDTO,
)

__all__ = [
    "ArgumentDTO",
    "BindingOrigin",
    "BodyDeclarationKind",
    "CoverageStatus",
    "DiagnosticDTO",
    "FieldDeclarationDTO",
    "FieldUseDTO",
    "ImportDTO",
    "InvocationDTO",
    "JavaParserProvenanceDTO",
    "MethodDeclarationDTO",
    "ParameterDTO",
    "ParsedJavaFileDTO",
    "RangeStatus",
    "ResolutionStatus",
    "SourceRangeDTO",
    "StrictFrozenModel",
    "TypeDeclarationDTO",
    "TypeRefDTO",
    "_require_contained",
]


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
