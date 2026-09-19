from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from codegraph.remediation.result_models import (
    build_generation_payload,
    build_no_fix_response,
)

__all__ = [
    "AGENTIC_FIX_STRATEGIES",
    "FIX_STRATEGIES",
    "NO_FIX_PREFIX",
    "STRUCTURED_GENERATION_FIELDS",
    "STRUCTURED_GENERATION_STOPS",
    "WEAK_CIPHER_LITERALS",
    "WEAK_RANDOM_PATTERNS",
    "build_generation_payload",
    "build_no_fix_response",
    "get_fix_strategy",
    "preflight_unsupported_reason",
    "resolve_context_source_code",
    "resolve_remediation_contract",
]

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
                "weak-random remediation only supports local Random/Math.random/ThreadLocalRandom/SHA1PRNG replacements"
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
    "ISO-A.8-LDAP-INJECTION": {
        "objective": "Prevent LDAP injection by applying RFC 4515 compliant filter encoding or parameterized search controls.",
        "allowed_transformations": [
            "Escape untrusted user input before constructing LDAP search filter expressions.",
            "Use SearchControls with parameterized arguments instead of raw string concatenation.",
        ],
        "non_goals": [
            "Do not alter directory schema or connection credentials.",
        ],
        "extra_examples": [],
    },
    "ISO-A.8-XPATH-INJECTION": {
        "objective": "Prevent XPath injection by parameterizing dynamic XPath queries using XPathVariableResolver.",
        "allowed_transformations": [
            "Bind untrusted variables using XPathVariableResolver or compile static XPath expressions with pre-compiled variables.",
        ],
        "non_goals": [
            "Do not modify XML document schemas or node structures.",
        ],
        "extra_examples": [],
    },
    "ISO-A.9.4.1": {
        "objective": "Enforce application access control on public HTTP endpoints.",
        "allowed_transformations": [
            "Add Spring Security annotations (e.g., @PreAuthorize('isAuthenticated()') or @Secured) to public controller endpoints.",
            "Add authentication principal or session validation before executing endpoint business logic.",
        ],
        "non_goals": [
            "Do not alter endpoint HTTP paths or response types.",
        ],
        "extra_examples": [],
    },
    "ISO-A.12.4.1": {
        "objective": "Record security event audit logging for sensitive application operations.",
        "allowed_transformations": [
            "Add structured audit logging calls using logger.info/logger.warn for critical transactions or state changes.",
        ],
        "non_goals": [
            "Do not log sensitive credentials or private tokens.",
        ],
        "extra_examples": [],
    },
}


def resolve_remediation_contract(
    rule_id: str,
    *,
    finding: dict[str, Any] | None = None,
    agentic: bool = False,
) -> dict[str, Any]:
    """Dynamically resolve remediation contract and guidance from finding metadata or catalog.

    Eliminates hardcoded per-rule heuristics by deriving objectives from finding properties
    (control_metadata, standard, title, summary, taint traces) and enforcing universal
    3-gate verification invariants, with seamless fallback for known ISO rules.
    """
    if agentic and rule_id in AGENTIC_FIX_STRATEGIES:
        base_strategy = dict(AGENTIC_FIX_STRATEGIES[rule_id])
        if finding:
            meta = finding.get("control_metadata") or {}
            if meta.get("summary"):
                base_strategy["summary"] = meta.get("summary")
        return base_strategy

    if not agentic and rule_id in FIX_STRATEGIES:
        return FIX_STRATEGIES[rule_id]

    meta = (finding.get("control_metadata") or {}) if finding else {}
    title = meta.get("title") or (finding.get("reason") if finding else None) or rule_id
    summary = meta.get("summary") or meta.get("description") or ""

    objective = f"Remediate security finding '{title}' ({rule_id}) at its root cause without breaking existing functionality."
    if summary:
        objective = f"{objective} Principle: {summary}"

    return {
        "rule_id": rule_id,
        "title": title,
        "summary": summary,
        "objective": objective,
        "allowed_transformations": [
            "Neutralize untrusted dataflow reaching the vulnerable sink via safe parameterization, framework sanitization, or constant decoupling.",
            "Make precise, surgical edits scoped strictly to the affected method or call chain.",
            "Add required standard library imports cleanly if new types are introduced.",
        ],
        "non_goals": [
            "Do not alter public method signatures, class hierarchy, or database schemas.",
            "Do not introduce new compiler errors, broken syntax, or unhandled exceptions.",
            "Do not perform unrelated stylistic or architectural refactorings.",
        ],
        "extra_examples": [],
    }


def get_fix_strategy(
    rule_id: str,
    *,
    finding: dict[str, Any] | None = None,
    agentic: bool = False,
) -> dict[str, Any]:
    """Retrieve the remediation guidance strategy for a rule, defaulting dynamically."""
    return resolve_remediation_contract(rule_id, finding=finding, agentic=agentic)
