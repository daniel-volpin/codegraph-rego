from __future__ import annotations

import re
from dataclasses import dataclass

from codegraph.policy.analysis.primitives import SourceSanitizer

WEAK_HASH_LITERAL_RE = re.compile(
    r'MessageDigest\s*\.\s*getInstance\s*\(\s*"([^"]+)"\s*(?:,|\))',
    re.IGNORECASE,
)
WEAK_HASH_VAR_RE = re.compile(
    r"MessageDigest\s*\.\s*getInstance\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)",
    re.IGNORECASE,
)
STRING_ASSIGN_RE = re.compile(
    r'(?:final\s+)?String\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"([^"]+)"',
    re.IGNORECASE,
)
CIPHER_LITERAL_RE = re.compile(
    r'Cipher\s*\.\s*getInstance\s*\(\s*"([^"]+)"\s*(?:,|\))',
    re.IGNORECASE,
)
INSECURE_RANDOM_PATTERNS = (
    re.compile(r"new\s+(?:java\.util\.)?Random\s*\(", re.IGNORECASE),
    re.compile(r"(?:java\.lang\.)?Math\s*\.\s*random\s*\(", re.IGNORECASE),
    re.compile(r"(?:java\.util\.concurrent\.)?ThreadLocalRandom\s*\.\s*current\s*\(", re.IGNORECASE),
)
SHA1_PRNG_RE = re.compile(
    r'(?:java\.security\.)?SecureRandom\s*\.\s*getInstance\s*\(\s*"SHA1PRNG"\s*\)',
    re.IGNORECASE,
)
WEAK_HASH_ALGORITHMS = frozenset({"md5", "sha1", "sha-1"})


@dataclass(frozen=True)
class CryptoAnalysis:
    md5_literal: bool
    md5_variable: bool
    weak_hash_literal: bool
    weak_hash_variable: bool
    weak_cipher_literal: bool
    insecure_random_detected: bool
    sha1prng_detected: bool


class CryptoIndicatorAnalyzer:
    def analyze(self, source_code: str) -> CryptoAnalysis:
        md5_literal = False
        md5_variable = False
        weak_hash_literal = False
        weak_hash_variable = False
        weak_cipher_literal = False
        insecure_random_detected = False
        sha1prng_detected = False

        for match in WEAK_HASH_LITERAL_RE.findall(source_code):
            normalized = match.strip().lower()
            if normalized not in WEAK_HASH_ALGORITHMS:
                continue
            weak_hash_literal = True
            if normalized == "md5":
                md5_literal = True

        assignments: dict[str, str] = {}
        for var, value in STRING_ASSIGN_RE.findall(source_code):
            normalized = value.strip().lower()
            if normalized in WEAK_HASH_ALGORITHMS:
                assignments[var] = value

        if assignments:
            for var in WEAK_HASH_VAR_RE.findall(source_code):
                if var in assignments:
                    weak_hash_variable = True
                    if assignments[var].strip().lower() == "md5":
                        md5_variable = True
                    break

        for algo in CIPHER_LITERAL_RE.findall(source_code):
            lowered = algo.strip().lower()
            if "des" in lowered or "rc4" in lowered or "ecb" in lowered:
                weak_cipher_literal = True
                break

        source_without_literals = SourceSanitizer.strip_comments_and_string_literals(source_code)
        if any(pattern.search(source_without_literals) for pattern in INSECURE_RANDOM_PATTERNS):
            insecure_random_detected = True

        if SHA1_PRNG_RE.search(source_code):
            sha1prng_detected = True

        return CryptoAnalysis(
            md5_literal=md5_literal,
            md5_variable=md5_variable,
            weak_hash_literal=weak_hash_literal,
            weak_hash_variable=weak_hash_variable,
            weak_cipher_literal=weak_cipher_literal,
            insecure_random_detected=insecure_random_detected,
            sha1prng_detected=sha1prng_detected,
        )
