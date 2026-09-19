from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator

from codegraph.java.models_base import (
    ArgumentDTO,
    BindingOrigin,
    BodyDeclarationKind,
    ParameterDTO,
    ResolutionStatus,
    SourceRangeDTO,
    StrictFrozenModel,
    TypeRefDTO,
)


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
