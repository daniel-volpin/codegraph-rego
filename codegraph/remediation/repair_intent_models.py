from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, Field


class RepairIntentKind(StrEnum):
    """Discriminator for the type of repair operation."""

    LITERAL_REPLACEMENT = "literal_replacement"
    CONSTRUCTOR_REPLACEMENT = "constructor_replacement"
    METHOD_CALL_REPLACEMENT = "method_call_replacement"
    IMPORT_ADJUSTMENT = "import_adjustment"
    NO_REPAIR = "no_repair"


class InvariantKind(StrEnum):
    """Classification of structural invariants the repair must preserve."""

    PRESERVE_METHOD_SIGNATURE = "preserve_method_signature"
    PRESERVE_API_CONTRACT = "preserve_api_contract"
    PRESERVE_TERMINAL_INVOCATION = "preserve_terminal_invocation"
    NO_CROSS_METHOD_REFACTOR = "no_cross_method_refactor"
    CUSTOM = "custom"


class RefusalCode(StrEnum):
    """Machine-readable reason codes for no-repair decisions."""

    UNSUPPORTED_RULE = "unsupported_rule"
    UNSUPPORTED_SUBCASE = "unsupported_subcase"
    MISSING_CONTEXT = "missing_context"
    MANUAL_REVIEW_REQUIRED = "manual_review_required"


class SourceSpan(BaseModel):
    """Identifies the Java method targeted for repair."""

    file_path: str
    method_signature: str
    start_line: int | None = None
    end_line: int | None = None


class Invariant(BaseModel):
    """A structural constraint the repair must honour."""

    kind: InvariantKind
    description: str


class TransformationSpec(BaseModel):
    """What the repair should accomplish, derived from ``FIX_STRATEGIES``."""

    objective: str
    allowed_transforms: list[str] = Field(default_factory=list)
    non_goals: list[str] = Field(default_factory=list)


class RefusalReason(BaseModel):
    """Typed explanation for why no repair is emitted."""

    code: RefusalCode
    explanation: str


class LiteralReplacementOp(BaseModel):
    """Find an exact string literal in source and replace it."""

    op_type: Literal["literal_replacement"] = "literal_replacement"
    target_value: str
    replacement_value: str
    qualifier_call: str | None = None


class ConstructorReplacementOp(BaseModel):
    """Replace a constructor call with a different class."""

    op_type: Literal["constructor_replacement"] = "constructor_replacement"
    old_type: str
    new_type: str
    preserve_suffix_chain: bool = True


class MethodCallReplacementOp(BaseModel):
    """Replace a static/instance method call expression."""

    op_type: Literal["method_call_replacement"] = "method_call_replacement"
    old_call_pattern: str
    new_call_expression: str


class ImportAdjustmentOp(BaseModel):
    """Declare an import addition or removal (informational in v1)."""

    op_type: Literal["import_adjustment"] = "import_adjustment"
    remove_import: str | None = None
    add_import: str | None = None


RepairOperation = Annotated[
    LiteralReplacementOp | ConstructorReplacementOp | MethodCallReplacementOp | ImportAdjustmentOp,
    Field(discriminator="op_type"),
]


class RepairIntent(BaseModel):
    """Typed intermediate representation of a planned repair operation."""

    kind: RepairIntentKind
    rule_id: str
    support_tier: Literal["full", "guarded", "manual"]
    target: SourceSpan
    transformation: TransformationSpec | None = None
    invariants: list[Invariant] = Field(default_factory=list)
    refusal: RefusalReason | None = None
    operations: list[RepairOperation] = Field(default_factory=list)
