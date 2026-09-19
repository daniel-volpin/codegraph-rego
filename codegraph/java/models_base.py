from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


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
    """Original-source range owned by the adapter."""

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
