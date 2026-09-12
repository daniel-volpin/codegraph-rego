from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

STRUCTURED_GENERATION_FIELDS = {"decision", "edits", "reason"}
STRUCTURED_GENERATION_STOPS = ["<|im_end|>", "<|endoftext|>"]
NO_FIX_PREFIX = "NO_FIX:"

# Weak-cipher literal subcases the deterministic remediation flow supports.
WEAK_CIPHER_LITERALS = (
    "des/cbc/pkcs5padding",
    "desede/ecb/pkcs5padding",
    "aes/ecb/",
    '"rc4"',
    'cipher.getinstance("des")',
    'cipher.getinstance("rc4")',
)

# Weak-randomness call patterns the deterministic remediation flow supports.
WEAK_RANDOM_PATTERNS = (
    r"new\s+(?:java\.util\.)?random\s*\(",
    r"(?:java\.lang\.)?math\s*\.\s*random\s*\(",
    r"(?:java\.util\.concurrent\.)?threadlocalrandom\s*\.\s*current\s*\(",
    r"(?:java\.security\.)?securerandom\s*\.\s*getinstance\s*\(\s*\"sha1prng\"\s*\)",
)


def resolve_context_source_code(context: Mapping[str, Any]) -> str:
    """Resolve the best-available method source for remediation decisions.

    Prefers ``exact_method_source`` captured during context assembly, then
    falls back to the policy evidence ``source_code`` view. Centralising this
    fallback keeps preflight, repair-intent planning, and prompt building in
    agreement about which source text they reason over.
    """
    evidence = context.get("evidence") or {}
    return str(context.get("exact_method_source") or evidence.get("source_code") or "")


def preflight_unsupported_reason(rule_id: str, source_code: str) -> str | None:
    """Return a human-readable reason if ``rule_id``'s subcase is unsupported.

    This is the single source of truth for subcase-level fixability shared by
    ``RemediationService._preflight_fixability_reason`` and the repair-intent
    planner's refusal check, so both paths produce identical semantics.
    """
    source_lower = source_code.lower()

    if rule_id == "ISO-A.10-WEAK-CRYPTO":
        has_supported_literal = any(literal in source_lower for literal in WEAK_CIPHER_LITERALS)
        if not has_supported_literal or "cipher.getinstance" not in source_lower:
            return (
                "weak-crypto remediation only supports explicit DES/RC4/AES-ECB "
                "literal subcases with local cipher context"
            )

    if rule_id == "ISO-A.10-WEAK-RANDOM":
        if not any(re.search(pattern, source_lower) for pattern in WEAK_RANDOM_PATTERNS):
            return (
                "weak-random remediation only supports local "
                "Random/Math.random/ThreadLocalRandom/SHA1PRNG replacements"
            )

    return None

FIX_STRATEGIES: dict[str, dict[str, Any]] = {
    "ISO-A.10-WEAK-HASH": {
        "objective": "Replace weak hash usage (MD5) with SHA-256 with minimal edits.",
        "allowed_transformations": [
            'Replace MessageDigest.getInstance("MD5") with MessageDigest.getInstance("SHA-256").',
            "Replace DigestUtils.md5* usage with a SHA-256 equivalent only if it is already available in the existing codebase context.",
        ],
        "non_goals": [
            "Do not change the method signature.",
            "Do not refactor unrelated code or rename variables.",
            "Do not add new logging or unrelated security changes.",
        ],
        "extra_examples": [],
    },
    "ISO-A.10-WEAK-RANDOM": {
        "objective": "Replace insecure randomness usage with SecureRandom-based generation using minimal local edits.",
        "allowed_transformations": [
            "Replace new Random() with new java.security.SecureRandom() without changing the surrounding method signature.",
            "Replace Math.random() with a local java.security.SecureRandom().nextDouble() call when the randomness use is method-local.",
            'Replace SecureRandom.getInstance("SHA1PRNG") with new java.security.SecureRandom() when no algorithm-specific behavior is required.',
            "Replace ThreadLocalRandom.current() with a method-local java.security.SecureRandom instance when the randomness is used for security-sensitive values.",
        ],
        "non_goals": [
            "Do not refactor logic across methods or introduce shared state.",
            "Do not change the method signature.",
            "Do not add unrelated security changes or logging.",
        ],
        "extra_examples": [],
    },
    "ISO-A.10-WEAK-CRYPTO": {
        "objective": "Replace weak literal cipher usage with a strong alternative only when the method already contains enough local context for a safe minimal edit.",
        "allowed_transformations": [
            "Replace DES/RC4/AES-ECB literal patterns with a stronger cipher transformation while keeping edits local to the method evidence.",
            "If a safe minimal fix is not possible with the given evidence, return NO_FIX.",
        ],
        "non_goals": [
            "Do not invent key management, IV/nonce generation, protocol changes, or storage formats.",
            "Do not change the method signature.",
            "Do not refactor unrelated code.",
        ],
        "extra_examples": [],
    },
}

AGENTIC_FIX_STRATEGIES: dict[str, dict[str, Any]] = {
    **FIX_STRATEGIES,
    "ISO-A.8-SQL-INJECTION": {
        "objective": "Replace dynamic SQL query concatenation with parameterized PreparedStatement.",
        "allowed_transformations": [
            "Convert Statement.executeQuery/executeUpdate into Connection.prepareStatement with ? placeholders.",
            "Bind query parameters using typed setter methods (e.g. setString, setInt).",
            "Add required java.sql.PreparedStatement imports.",
        ],
        "non_goals": [
            "Do not alter database table or column names.",
            "Do not change method return types.",
        ],
        "extra_examples": [],
    },
    "ISO-A.8-PATH-TRAVERSAL": {
        "objective": "Prevent path traversal by verifying canonical base directory containment.",
        "allowed_transformations": [
            "Normalize paths using Path.normalize() and verify canonical containment against the base directory.",
            "Use Path.resolve() instead of string concatenation for file paths.",
        ],
        "non_goals": [
            "Do not change file permissions or filesystem structure.",
        ],
        "extra_examples": [],
    },
    "ISO-A.8-CMD-INJECTION": {
        "objective": "Prevent command injection by using structured argument arrays with ProcessBuilder.",
        "allowed_transformations": [
            "Replace Runtime.getRuntime().exec string concatenation with ProcessBuilder argument arrays.",
            "Pass individual command arguments as separate array elements to prevent shell token splitting.",
        ],
        "non_goals": [
            "Do not modify the underlying executable or external environment.",
        ],
        "extra_examples": [],
    },
}

_DYNAMIC_FIX_STRATEGIES: dict[str, dict[str, Any]] = {}


def register_fix_strategy(rule_id: str, strategy: dict[str, Any], *, agentic: bool = True) -> None:
    """Dynamically register a custom remediation strategy for a policy rule."""
    _DYNAMIC_FIX_STRATEGIES[rule_id] = strategy
    if agentic:
        AGENTIC_FIX_STRATEGIES[rule_id] = strategy
    else:
        FIX_STRATEGIES[rule_id] = strategy


def get_fix_strategy(rule_id: str, *, agentic: bool = False) -> dict[str, Any] | None:
    """Retrieve the remediation guidance strategy for a rule."""
    if rule_id in _DYNAMIC_FIX_STRATEGIES:
        return _DYNAMIC_FIX_STRATEGIES[rule_id]
    if agentic:
        return AGENTIC_FIX_STRATEGIES.get(rule_id)
    return FIX_STRATEGIES.get(rule_id)


def build_generation_payload(
    *,
    decision: str | None,
    edits: list[dict[str, Any]] | None,
    replacement_method_lines: list[str] | None,
    replacement_method_code: str | None,
    reason: str | None,
    raw_response_valid: bool,
    schema_error: str | None,
) -> dict[str, Any]:
    return {
        "decision": decision,
        "edits": edits,
        "replacement_method_lines": replacement_method_lines,
        "replacement_method_code": replacement_method_code,
        "reason": reason,
        "raw_response_valid": raw_response_valid,
        "schema_error": schema_error,
    }


def build_no_fix_response(
    *,
    violation_id: str,
    context: dict[str, Any],
    reason: str,
    attempt_count: int | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "status": "NO_FIX",
        "error": f"{NO_FIX_PREFIX} {reason}",
        "violation_id": violation_id,
        "method_key": context.get("method_key"),
        "target_method": context.get("target_method"),
        "file_path": context.get("file_path"),
        "rule_id": context.get("rule_id"),
        "generation": {
            "decision": "no_fix",
            "edits": [],
            "replacement_method_lines": None,
            "replacement_method_code": None,
            "reason": reason,
            "raw_response_valid": True,
            "schema_error": None,
        },
    }
    if attempt_count is not None:
        payload["attempt_count"] = attempt_count
    return payload
