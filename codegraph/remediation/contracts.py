from __future__ import annotations

from typing import Any

STRUCTURED_GENERATION_FIELDS = {"decision", "edits", "reason"}
STRUCTURED_GENERATION_STOPS = ["<|im_end|>", "<|endoftext|>"]
NO_FIX_PREFIX = "NO_FIX:"

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
