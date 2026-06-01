"""
Typed Repair Intent IR for bounded Java security remediation planning.

This module defines a structured intermediate representation that captures
*what* repair operation should be performed and *why*, without yet producing
the actual code edits.  It sits between capability/preflight checks and
LLM-based code generation, giving the system a serialisable, validated
contract that future deterministic patch compilation can consume.

Current status: **shadow-mode only**.  The planner is callable from the
remediation service for logging and artifact purposes but does not alter
the existing LLM prompting, parsing, or verification flows.
"""

from __future__ import annotations

import logging
import re
from enum import StrEnum
from typing import Annotated, Any, Literal, Union

from pydantic import BaseModel, Field

from codegraph.remediation.capabilities import (
    RemediationCapability,
    get_remediation_capability,
)
from codegraph.remediation.contracts import FIX_STRATEGIES

LOGGER = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Operation specs (Step 2) — typed executable descriptions of each edit
# ---------------------------------------------------------------------------


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
    Union[
        LiteralReplacementOp,
        ConstructorReplacementOp,
        MethodCallReplacementOp,
        ImportAdjustmentOp,
    ],
    Field(discriminator="op_type"),
]


class RepairIntent(BaseModel):
    """
    Typed intermediate representation of a planned repair operation.

    This is the core IR produced by :func:`plan_repair_intent`.  It is
    designed to be serialisable (``model_dump`` / ``model_validate``),
    round-trippable, and suitable for persistence as a JSON artifact.

    ``transformation`` is the LLM-prompt-oriented description layer.
    ``operations`` is the compiler-oriented executable specification.
    """

    kind: RepairIntentKind
    rule_id: str
    support_tier: Literal["full", "guarded", "manual"]
    target: SourceSpan
    transformation: TransformationSpec | None = None
    invariants: list[Invariant] = Field(default_factory=list)
    refusal: RefusalReason | None = None
    operations: list[RepairOperation] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Rule → intent-kind mapping
# ---------------------------------------------------------------------------

_RULE_INTENT_KIND: dict[str, RepairIntentKind] = {
    "ISO-A.10-WEAK-HASH": RepairIntentKind.LITERAL_REPLACEMENT,
    "ISO-A.10-WEAK-RANDOM": RepairIntentKind.CONSTRUCTOR_REPLACEMENT,
    "ISO-A.10-WEAK-CRYPTO": RepairIntentKind.LITERAL_REPLACEMENT,
}

_DEFAULT_INVARIANTS: list[Invariant] = [
    Invariant(
        kind=InvariantKind.PRESERVE_METHOD_SIGNATURE,
        description="Do not change the method signature.",
    ),
    Invariant(
        kind=InvariantKind.NO_CROSS_METHOD_REFACTOR,
        description="Do not refactor logic across methods or introduce shared state.",
    ),
]


# ---------------------------------------------------------------------------
# Preflight helpers (mirrors service._preflight_fixability_reason semantics)
# ---------------------------------------------------------------------------


def _preflight_refusal(rule_id: str, source_code: str) -> RefusalReason | None:
    """Check subcase-level fixability.

    This deliberately mirrors the regex/literal checks in
    ``RemediationService._preflight_fixability_reason`` so that the
    repair-intent planner produces identical refusal semantics without
    altering the existing service code path.
    """
    source_lower = source_code.lower()

    if rule_id == "ISO-A.10-WEAK-CRYPTO":
        weak_cipher_literals = (
            "des/cbc/pkcs5padding",
            "desede/ecb/pkcs5padding",
            "aes/ecb/",
            '"rc4"',
            'cipher.getinstance("des")',
            'cipher.getinstance("rc4")',
        )
        has_supported_literal = any(literal in source_lower for literal in weak_cipher_literals)
        if not has_supported_literal or "cipher.getinstance" not in source_lower:
            return RefusalReason(
                code=RefusalCode.UNSUPPORTED_SUBCASE,
                explanation=(
                    "weak-crypto remediation only supports explicit "
                    "DES/RC4/AES-ECB literal subcases with local cipher context"
                ),
            )

    if rule_id == "ISO-A.10-WEAK-RANDOM":
        supported_patterns = (
            r"new\s+(?:java\.util\.)?random\s*\(",
            r"(?:java\.lang\.)?math\s*\.\s*random\s*\(",
            r"(?:java\.util\.concurrent\.)?threadlocalrandom\s*\.\s*current\s*\(",
            r"(?:java\.security\.)?securerandom\s*\.\s*getinstance\s*\(\s*\"sha1prng\"\s*\)",
        )
        if not any(re.search(pattern, source_lower) for pattern in supported_patterns):
            return RefusalReason(
                code=RefusalCode.UNSUPPORTED_SUBCASE,
                explanation=(
                    "weak-random remediation only supports local "
                    "Random/Math.random/ThreadLocalRandom/SHA1PRNG replacements"
                ),
            )

    return None


# ---------------------------------------------------------------------------
# Planner
# ---------------------------------------------------------------------------


def plan_repair_intent(
    context: dict[str, Any],
    capability: RemediationCapability | None = None,
    *,
    supported_rule_ids: set[str] | None = None,
) -> RepairIntent:
    """Derive a typed :class:`RepairIntent` from violation context.

    Parameters
    ----------
    context:
        The violation context dict produced by
        ``RemediationService.get_violation_context``.
    capability:
        Pre-resolved capability. When *None*, the function resolves it
        internally via :func:`get_remediation_capability`.
    supported_rule_ids:
        Optional override for the supported rule-id set (forwarded to
        :func:`get_remediation_capability` when *capability* is None).

    Returns
    -------
    RepairIntent
        A fully validated, serialisable intent IR.
    """
    rule_id = str(context.get("rule_id") or "")
    target_method = str(context.get("target_method") or "unknown")
    file_path = str(context.get("file_path") or "unknown")
    evidence = context.get("evidence") or {}

    # Build a minimal SourceSpan from available context.
    target = SourceSpan(
        file_path=file_path,
        method_signature=target_method,
    )

    # Resolve capability if not provided.
    if capability is None:
        capability = get_remediation_capability(
            rule_id,
            supported_rule_ids=supported_rule_ids or FIX_STRATEGIES.keys(),
        )

    # Unsupported rule → no_repair.
    if not capability.supported:
        LOGGER.debug(
            "RepairIntent: no_repair for unsupported rule %s (%s)",
            rule_id,
            capability.reason_code,
        )
        return RepairIntent(
            kind=RepairIntentKind.NO_REPAIR,
            rule_id=rule_id,
            support_tier="manual",
            target=target,
            refusal=RefusalReason(
                code=RefusalCode.UNSUPPORTED_RULE,
                explanation=capability.rationale,
            ),
        )

    # Preflight subcase check.
    source_code = str(context.get("exact_method_source") or evidence.get("source_code") or "")
    preflight = _preflight_refusal(rule_id, source_code)
    if preflight is not None:
        LOGGER.debug(
            "RepairIntent: no_repair for preflight refusal on %s (%s)",
            rule_id,
            preflight.code,
        )
        return RepairIntent(
            kind=RepairIntentKind.NO_REPAIR,
            rule_id=rule_id,
            support_tier=capability.support_tier,
            target=target,
            refusal=preflight,
        )

    # Build transformation spec from FIX_STRATEGIES.
    strategy = FIX_STRATEGIES.get(rule_id) or {}
    transformation = TransformationSpec(
        objective=str(strategy.get("objective") or "").strip(),
        allowed_transforms=list(strategy.get("allowed_transformations") or []),
        non_goals=list(strategy.get("non_goals") or []),
    )

    # Determine intent kind.
    kind = _RULE_INTENT_KIND.get(rule_id, RepairIntentKind.LITERAL_REPLACEMENT)

    # Assemble invariants.
    invariants = list(_DEFAULT_INVARIANTS)
    if kind == RepairIntentKind.CONSTRUCTOR_REPLACEMENT:
        invariants.append(
            Invariant(
                kind=InvariantKind.PRESERVE_TERMINAL_INVOCATION,
                description="Preserve downstream invocation contract when upgrading a constructor chain.",
            )
        )

    # Build typed operations.
    operations = _build_operations(rule_id, source_code)

    intent = RepairIntent(
        kind=kind,
        rule_id=rule_id,
        support_tier=capability.support_tier,
        target=target,
        transformation=transformation,
        invariants=invariants,
        operations=operations,
    )

    LOGGER.debug(
        "RepairIntent: planned %s for %s (tier=%s, ops=%d)",
        intent.kind,
        rule_id,
        intent.support_tier,
        len(intent.operations),
    )
    return intent


# ---------------------------------------------------------------------------
# Operation builders (per-rule)
# ---------------------------------------------------------------------------


def _build_operations(rule_id: str, source_code: str) -> list[RepairOperation]:
    """Derive typed executable operations from the rule and source code."""
    builder = _OPERATION_BUILDERS.get(rule_id)
    if builder is None:
        return []
    return builder(source_code)


def _build_weak_hash_ops(source_code: str) -> list[RepairOperation]:
    """Build operations for ISO-A.10-WEAK-HASH."""
    ops: list[RepairOperation] = []
    source_lower = source_code.lower()

    if '"md5"' in source_lower:
        ops.append(
            LiteralReplacementOp(
                target_value='"MD5"',
                replacement_value='"SHA-256"',
                qualifier_call="MessageDigest.getInstance",
            )
        )
    if '"sha-1"' in source_lower or '"sha1"' in source_lower:
        ops.append(
            LiteralReplacementOp(
                target_value='"SHA-1"',
                replacement_value='"SHA-256"',
                qualifier_call="MessageDigest.getInstance",
            )
        )

    # Fallback: if we matched the rule but found no specific literal,
    # emit a generic MD5 → SHA-256 operation.
    if not ops:
        ops.append(
            LiteralReplacementOp(
                target_value='"MD5"',
                replacement_value='"SHA-256"',
                qualifier_call="MessageDigest.getInstance",
            )
        )
    return ops


def _build_weak_random_ops(source_code: str) -> list[RepairOperation]:
    """Build operations for ISO-A.10-WEAK-RANDOM."""
    ops: list[RepairOperation] = []
    source_lower = source_code.lower()

    if re.search(r"new\s+(?:java\.util\.)?random\s*\(", source_lower):
        ops.append(
            ConstructorReplacementOp(
                old_type="java.util.Random",
                new_type="java.security.SecureRandom",
                preserve_suffix_chain=True,
            )
        )
    if re.search(r"(?:java\.lang\.)?math\s*\.\s*random\s*\(", source_lower):
        ops.append(
            MethodCallReplacementOp(
                old_call_pattern="Math.random()",
                new_call_expression="new java.security.SecureRandom().nextDouble()",
            )
        )
    if re.search(r"(?:java\.util\.concurrent\.)?threadlocalrandom\s*\.\s*current\s*\(", source_lower):
        ops.append(
            MethodCallReplacementOp(
                old_call_pattern="ThreadLocalRandom.current()",
                new_call_expression="new java.security.SecureRandom()",
            )
        )
    if re.search(
        r"(?:java\.security\.)?securerandom\s*\.\s*getinstance\s*\(\s*\"sha1prng\"\s*\)",
        source_lower,
    ):
        ops.append(
            MethodCallReplacementOp(
                old_call_pattern='SecureRandom.getInstance("SHA1PRNG")',
                new_call_expression="new java.security.SecureRandom()",
            )
        )
    return ops


def _build_weak_crypto_ops(source_code: str) -> list[RepairOperation]:
    """Build operations for ISO-A.10-WEAK-CRYPTO (guarded)."""
    ops: list[RepairOperation] = []
    source_lower = source_code.lower()

    if "des/cbc/pkcs5padding" in source_lower:
        ops.append(
            LiteralReplacementOp(
                target_value='"DES/CBC/PKCS5Padding"',
                replacement_value='"AES/GCM/NoPadding"',
                qualifier_call="Cipher.getInstance",
            )
        )
    if "desede/ecb/pkcs5padding" in source_lower:
        ops.append(
            LiteralReplacementOp(
                target_value='"DESede/ECB/PKCS5Padding"',
                replacement_value='"AES/GCM/NoPadding"',
                qualifier_call="Cipher.getInstance",
            )
        )
    if "aes/ecb/" in source_lower:
        ops.append(
            LiteralReplacementOp(
                target_value='"AES/ECB/',
                replacement_value='"AES/GCM/NoPadding"',
                qualifier_call="Cipher.getInstance",
            )
        )
    if '"rc4"' in source_lower:
        ops.append(
            LiteralReplacementOp(
                target_value='"RC4"',
                replacement_value='"AES/GCM/NoPadding"',
                qualifier_call="Cipher.getInstance",
            )
        )
    if 'cipher.getinstance("des")' in source_lower:
        ops.append(
            LiteralReplacementOp(
                target_value='"DES"',
                replacement_value='"AES/GCM/NoPadding"',
                qualifier_call="Cipher.getInstance",
            )
        )
    return ops


_OPERATION_BUILDERS: dict[str, Any] = {
    "ISO-A.10-WEAK-HASH": _build_weak_hash_ops,
    "ISO-A.10-WEAK-RANDOM": _build_weak_random_ops,
    "ISO-A.10-WEAK-CRYPTO": _build_weak_crypto_ops,
}
