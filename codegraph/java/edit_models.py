from __future__ import annotations

import base64
import hashlib
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class JavaSourceEditDTO(BaseModel):
    """Validated response from the JDT source-edit process boundary."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["codegraph-java-edit/v1"] = "codegraph-java-edit/v1"
    operation: Literal["ensure_import"] = "ensure_import"
    status: Literal["APPLIED", "UNCHANGED", "REJECTED"]
    relative_path: str
    qualified_name: str
    is_static: bool = False
    on_demand: bool = False
    source_sha256_before: str
    source_sha256_after: str
    source_byte_length: int = Field(ge=0)
    source_base64: str
    reason: str
    errors: tuple[str, ...] = ()

    @field_validator("source_sha256_before", "source_sha256_after")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        if len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
            raise ValueError("source hashes must be 64 lowercase hexadecimal characters")
        return value

    @field_validator("relative_path", "qualified_name", "reason")
    @classmethod
    def validate_non_empty(cls, value: str) -> str:
        if not value:
            raise ValueError("value must not be empty")
        return value

    @model_validator(mode="after")
    def validate_source_payload(self) -> JavaSourceEditDTO:
        try:
            decoded = base64.b64decode(self.source_base64, validate=True)
        except ValueError as exc:
            raise ValueError("source_base64 must be valid base64") from exc
        if len(decoded) != self.source_byte_length:
            raise ValueError("source_byte_length must match decoded source bytes")
        if hashlib.sha256(decoded).hexdigest() != self.source_sha256_after:
            raise ValueError("source_sha256_after must match decoded source bytes")
        if self.status in {"UNCHANGED", "REJECTED"} and self.source_sha256_after != self.source_sha256_before:
            raise ValueError(f"{self.status} edits must preserve source bytes")
        if self.status == "APPLIED" and self.source_sha256_after == self.source_sha256_before:
            raise ValueError("APPLIED edits must change source bytes")
        if self.status == "REJECTED" and not (self.reason or self.errors):
            raise ValueError("REJECTED edits require a reason or errors")
        return self

    @property
    def source_bytes(self) -> bytes:
        return base64.b64decode(self.source_base64, validate=True)
