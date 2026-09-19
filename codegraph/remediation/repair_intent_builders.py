from __future__ import annotations

import re
from typing import Any

from codegraph.remediation.contracts import preflight_unsupported_reason
from codegraph.remediation.repair_intent_models import (
    ConstructorReplacementOp,
    Invariant,
    InvariantKind,
    LiteralReplacementOp,
    MethodCallReplacementOp,
    RefusalCode,
    RefusalReason,
    RepairIntentKind,
    RepairOperation,
)

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


def _preflight_refusal(rule_id: str, source_code: str) -> RefusalReason | None:
    reason = preflight_unsupported_reason(rule_id, source_code)
    if reason is not None:
        return RefusalReason(code=RefusalCode.UNSUPPORTED_SUBCASE, explanation=reason)
    return None


def _build_weak_hash_ops(source_code: str) -> list[RepairOperation]:
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


def build_operations(rule_id: str, source_code: str) -> list[RepairOperation]:
    builder = _OPERATION_BUILDERS.get(rule_id)
    if builder is None:
        return []
    return builder(source_code)
