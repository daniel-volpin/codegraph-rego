from __future__ import annotations

import re
from typing import Dict

_MD5_LITERAL_RE = re.compile(
    r"MessageDigest\s*\.\s*getInstance\s*\(\s*\"([^\"]+)\"\s*\)",
    re.IGNORECASE,
)
_MD5_VAR_RE = re.compile(
    r"MessageDigest\s*\.\s*getInstance\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)",
    re.IGNORECASE,
)
_STRING_ASSIGN_RE = re.compile(
    r"(?:final\s+)?String\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\"([^\"]+)\"",
    re.IGNORECASE,
)
_CIPHER_LITERAL_RE = re.compile(
    r"Cipher\s*\.\s*getInstance\s*\(\s*\"([^\"]+)\"\s*\)",
    re.IGNORECASE,
)


def analyze_crypto_indicators(source_code: str) -> Dict[str, bool]:
    if not source_code:
        return {
            "md5_literal": False,
            "md5_variable": False,
            "md5_detected": False,
            "weak_cipher_literal": False,
            "weak_cipher_detected": False,
        }

    md5_literal = False
    md5_variable = False
    weak_cipher_literal = False

    for match in _MD5_LITERAL_RE.findall(source_code):
        if match.strip().lower() == "md5":
            md5_literal = True
            break

    assignments = {}
    for var, value in _STRING_ASSIGN_RE.findall(source_code):
        if value.strip().lower() == "md5":
            assignments[var] = value

    if assignments:
        for var in _MD5_VAR_RE.findall(source_code):
            if var in assignments:
                md5_variable = True
                break

    for algo in _CIPHER_LITERAL_RE.findall(source_code):
        lowered = algo.strip().lower()
        if "des" in lowered or "rc4" in lowered or "ecb" in lowered:
            weak_cipher_literal = True
            break

    md5_detected = md5_literal or md5_variable
    weak_cipher_detected = weak_cipher_literal
    return {
        "md5_literal": md5_literal,
        "md5_variable": md5_variable,
        "md5_detected": md5_detected,
        "weak_cipher_literal": weak_cipher_literal,
        "weak_cipher_detected": weak_cipher_detected,
    }
