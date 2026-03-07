from __future__ import annotations

import re
from typing import Dict

_MD5_LITERAL_RE = re.compile(
    r"MessageDigest\s*\.\s*getInstance\s*\(\s*\"([^\"]+)\"\s*(?:,|\))",
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
    r"Cipher\s*\.\s*getInstance\s*\(\s*\"([^\"]+)\"\s*(?:,|\))",
    re.IGNORECASE,
)
_INSECURE_RANDOM_PATTERNS = (
    re.compile(r"new\s+(?:java\.util\.)?Random\s*\(", re.IGNORECASE),
    re.compile(r"(?:java\.lang\.)?Math\s*\.\s*random\s*\(", re.IGNORECASE),
    re.compile(r"(?:java\.util\.concurrent\.)?ThreadLocalRandom\s*\.\s*current\s*\(", re.IGNORECASE),
)
_SHA1_PRNG_RE = re.compile(
    r"(?:java\.security\.)?SecureRandom\s*\.\s*getInstance\s*\(\s*\"SHA1PRNG\"\s*\)",
    re.IGNORECASE,
)
_UNTRUSTED_INPUT_PATTERNS = (
    re.compile(r"getParameter\s*\(", re.IGNORECASE),
    re.compile(r"getHeader\s*\(", re.IGNORECASE),
    re.compile(r"getQueryString\s*\(", re.IGNORECASE),
    re.compile(r"getCookies\s*\(", re.IGNORECASE),
)
_PATH_TRAVERSAL_PATTERNS = (
    re.compile(r"new\s+java\.io\.File\s*\(", re.IGNORECASE),
    re.compile(r"new\s+java\.io\.FileInputStream\s*\(", re.IGNORECASE),
    re.compile(r"Files\s*\.\s*newInputStream\s*\(", re.IGNORECASE),
    re.compile(r"Paths\s*\.\s*get\s*\(", re.IGNORECASE),
    re.compile(r"new\s+java\.io\.FileReader\s*\(", re.IGNORECASE),
)
_CMDI_PATTERNS = (
    re.compile(r"Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(", re.IGNORECASE),
    re.compile(r"new\s+ProcessBuilder\s*\(", re.IGNORECASE),
    re.compile(r"\.command\s*\(", re.IGNORECASE),
)
_LDAP_PATTERNS = (
    re.compile(r"InitialDirContext", re.IGNORECASE),
    re.compile(r"DirContext", re.IGNORECASE),
    re.compile(r"\.search\s*\(", re.IGNORECASE),
)
_XPATH_PATTERNS = (
    re.compile(r"XPathFactory\s*\.\s*newInstance\s*\(", re.IGNORECASE),
    re.compile(r"\.evaluate\s*\(", re.IGNORECASE),
)
_SQL_PREPARE_CALL_RE = re.compile(r"prepareCall\s*\(", re.IGNORECASE)
_SQL_CALLABLE_STATEMENT_RE = re.compile(r"CallableStatement", re.IGNORECASE)


def analyze_policy_indicators(source_code: str) -> Dict[str, bool]:
    if not source_code:
        return {
            "md5_literal": False,
            "md5_variable": False,
            "md5_detected": False,
            "weak_cipher_literal": False,
            "weak_cipher_detected": False,
            "insecure_random_detected": False,
            "sha1prng_detected": False,
            "path_traversal_detected": False,
            "command_injection_detected": False,
            "ldap_injection_detected": False,
            "xpath_injection_detected": False,
            "sql_prepare_call_detected": False,
            "sql_callable_statement_detected": False,
        }

    untrusted_input_detected = any(pattern.search(source_code) for pattern in _UNTRUSTED_INPUT_PATTERNS)
    md5_literal = False
    md5_variable = False
    weak_cipher_literal = False
    insecure_random_detected = False
    sha1prng_detected = False

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

    if any(pattern.search(source_code) for pattern in _INSECURE_RANDOM_PATTERNS):
        insecure_random_detected = True

    if _SHA1_PRNG_RE.search(source_code):
        insecure_random_detected = True
        sha1prng_detected = True

    path_traversal_detected = (
        untrusted_input_detected and "+" in source_code and any(pattern.search(source_code) for pattern in _PATH_TRAVERSAL_PATTERNS)
    )
    command_injection_detected = (
        untrusted_input_detected and "+" in source_code and any(pattern.search(source_code) for pattern in _CMDI_PATTERNS)
    )
    ldap_injection_detected = (
        untrusted_input_detected and "+" in source_code and all(pattern.search(source_code) for pattern in _LDAP_PATTERNS)
    )
    xpath_injection_detected = (
        untrusted_input_detected and "+" in source_code and all(pattern.search(source_code) for pattern in _XPATH_PATTERNS)
    )
    sql_prepare_call_detected = bool(_SQL_PREPARE_CALL_RE.search(source_code))
    sql_callable_statement_detected = bool(_SQL_CALLABLE_STATEMENT_RE.search(source_code))

    md5_detected = md5_literal or md5_variable
    weak_cipher_detected = weak_cipher_literal
    return {
        "md5_literal": md5_literal,
        "md5_variable": md5_variable,
        "md5_detected": md5_detected,
        "weak_cipher_literal": weak_cipher_literal,
        "weak_cipher_detected": weak_cipher_detected,
        "insecure_random_detected": insecure_random_detected,
        "sha1prng_detected": sha1prng_detected,
        "path_traversal_detected": path_traversal_detected,
        "command_injection_detected": command_injection_detected,
        "ldap_injection_detected": ldap_injection_detected,
        "xpath_injection_detected": xpath_injection_detected,
        "sql_prepare_call_detected": sql_prepare_call_detected,
        "sql_callable_statement_detected": sql_callable_statement_detected,
    }


def analyze_crypto_indicators(source_code: str) -> Dict[str, bool]:
    return analyze_policy_indicators(source_code)
