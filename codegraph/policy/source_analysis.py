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
_SQL_UNTRUSTED_INPUT_PATTERNS = (
    *_UNTRUSTED_INPUT_PATTERNS,
    re.compile(r"getParameterMap\s*\(", re.IGNORECASE),
    re.compile(r"getParameterValues\s*\(", re.IGNORECASE),
    re.compile(r"getParameterNames\s*\(", re.IGNORECASE),
    re.compile(r"getHeaders\s*\(", re.IGNORECASE),
    re.compile(r"getTheParameter\s*\(", re.IGNORECASE),
)
_PATH_TRAVERSAL_PATTERNS = (
    re.compile(r"new\s+java\.io\.File\s*\(", re.IGNORECASE),
    re.compile(r"new\s+java\.io\.FileInputStream\s*\(", re.IGNORECASE),
    re.compile(r"new\s+java\.io\.FileOutputStream\s*\(", re.IGNORECASE),
    re.compile(r"Files\s*\.\s*newInputStream\s*\(", re.IGNORECASE),
    re.compile(r"Paths\s*\.\s*get\s*\(", re.IGNORECASE),
    re.compile(r"new\s+java\.io\.FileReader\s*\(", re.IGNORECASE),
)
_PATH_DYNAMIC_CONSTRUCTION_PATTERNS = (
    re.compile(r"\b(?:file|path|uri)\w*\s*=\s*[^;\n]*\+", re.IGNORECASE),
    re.compile(
        r"new\s+java\.io\.(?:File|FileInputStream|FileOutputStream|FileReader)\s*\([^;\n]*\+",
        re.IGNORECASE,
    ),
    re.compile(r"new\s+java\.net\.URI\s*\([^;\n]*\+", re.IGNORECASE),
)
_PATH_DYNAMIC_ARGUMENT_PATTERNS = (
    re.compile(r"new\s+java\.io\.File\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*(?:,|\))", re.IGNORECASE),
    re.compile(r"new\s+java\.io\.FileInputStream\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*(?:,|\))", re.IGNORECASE),
    re.compile(r"new\s+java\.io\.FileOutputStream\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*(?:,|\))", re.IGNORECASE),
    re.compile(r"new\s+java\.io\.FileReader\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*(?:,|\))", re.IGNORECASE),
    re.compile(r"Paths\s*\.\s*get\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*(?:,|\))", re.IGNORECASE),
)
_CMDI_PATTERNS = (
    re.compile(r"\.exec\s*\(", re.IGNORECASE),
    re.compile(r"new\s+ProcessBuilder\s*\(", re.IGNORECASE),
    re.compile(r"\.command\s*\(", re.IGNORECASE),
)
_COMMAND_VARIABLE_EXEC_PATTERN = re.compile(r"\.exec\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*(?:,|\))", re.IGNORECASE)
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
_SQL_PREPARE_STATEMENT_RE = re.compile(r"prepareStatement\s*\(", re.IGNORECASE)
_SQL_CALLABLE_STATEMENT_RE = re.compile(r"CallableStatement", re.IGNORECASE)
_SQL_EXECUTE_CALL_PATTERNS = (
    re.compile(r"\.executeQuery\s*\(", re.IGNORECASE),
    re.compile(r"\.executeUpdate\s*\(", re.IGNORECASE),
    re.compile(r"\.execute\s*\(", re.IGNORECASE),
    re.compile(r"JDBCtemplate\s*\.\s*(?:execute|queryForMap|queryForRowSet|queryForList|update)\s*\(", re.IGNORECASE),
)
_STRING_BUILDER_RE = re.compile(r"String(?:Builder|Buffer)", re.IGNORECASE)
_APPEND_CALL_RE = re.compile(r"\.append\s*\(", re.IGNORECASE)
_ARRAY_LITERAL_RE = re.compile(r"\{[^{}]*[A-Za-z_][A-Za-z0-9_]*[^{}]*\}")
_STRING_CONCAT_PATTERNS = (
    re.compile(r'"[^"\n]*"\s*\+\s*[A-Za-z_(]', re.IGNORECASE),
    re.compile(r"[A-Za-z_][A-Za-z0-9_.)]*\s*\+\s*\"[^\n]*\"", re.IGNORECASE),
    re.compile(r"[A-Za-z_][A-Za-z0-9_.)]*\s*\+\s*[A-Za-z_][A-Za-z0-9_.(]*", re.IGNORECASE),
)


def _strip_comments_and_string_literals(source_code: str) -> str:
    if not source_code:
        return source_code

    sanitized: list[str] = []
    in_block_comment = False
    in_string = False
    in_char = False
    escaped = False
    quote_char = ""
    index = 0

    while index < len(source_code):
        char = source_code[index]
        nxt = source_code[index + 1] if index + 1 < len(source_code) else ""

        if in_block_comment:
            if char == "*" and nxt == "/":
                sanitized.extend("  ")
                in_block_comment = False
                index += 2
                continue
            sanitized.append("\n" if char == "\n" else " ")
            index += 1
            continue

        if in_string or in_char:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote_char:
                if in_string:
                    in_string = False
                else:
                    in_char = False
            sanitized.append("\n" if char == "\n" else " ")
            index += 1
            continue

        if char == "/" and nxt == "/":
            sanitized.extend("  ")
            index += 2
            while index < len(source_code) and source_code[index] != "\n":
                sanitized.append(" ")
                index += 1
            continue

        if char == "/" and nxt == "*":
            sanitized.extend("  ")
            in_block_comment = True
            index += 2
            continue

        if char == '"':
            in_string = True
            quote_char = '"'
            sanitized.append(" ")
            index += 1
            continue

        if char == "'":
            in_char = True
            quote_char = "'"
            sanitized.append(" ")
            index += 1
            continue

        sanitized.append(char)
        index += 1

    return "".join(sanitized)


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
    sql_untrusted_input_detected = any(pattern.search(source_code) for pattern in _SQL_UNTRUSTED_INPUT_PATTERNS)
    builder_append_detected = bool(_STRING_BUILDER_RE.search(source_code) and _APPEND_CALL_RE.search(source_code))
    dynamic_construction_detected = builder_append_detected or any(
        pattern.search(source_code) for pattern in _STRING_CONCAT_PATTERNS
    )
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

    source_without_literals = _strip_comments_and_string_literals(source_code)

    if any(pattern.search(source_without_literals) for pattern in _INSECURE_RANDOM_PATTERNS):
        insecure_random_detected = True

    if _SHA1_PRNG_RE.search(source_code):
        insecure_random_detected = True
        sha1prng_detected = True

    path_dynamic_usage_detected = any(pattern.search(source_code) for pattern in _PATH_DYNAMIC_CONSTRUCTION_PATTERNS) or any(
        pattern.search(source_code) for pattern in _PATH_DYNAMIC_ARGUMENT_PATTERNS
    )
    path_traversal_detected = (
        untrusted_input_detected
        and any(pattern.search(source_code) for pattern in _PATH_TRAVERSAL_PATTERNS)
        and path_dynamic_usage_detected
    )
    command_argument_detected = bool(_ARRAY_LITERAL_RE.search(source_code) or _COMMAND_VARIABLE_EXEC_PATTERN.search(source_code))
    command_injection_detected = (
        untrusted_input_detected
        and any(pattern.search(source_code) for pattern in _CMDI_PATTERNS)
        and (dynamic_construction_detected or command_argument_detected)
    )
    ldap_injection_detected = (
        untrusted_input_detected
        and any(pattern.search(source_code) for pattern in _LDAP_PATTERNS[:2])
        and bool(_LDAP_PATTERNS[2].search(source_code))
        and dynamic_construction_detected
    )
    xpath_injection_detected = (
        untrusted_input_detected
        and all(pattern.search(source_code) for pattern in _XPATH_PATTERNS)
        and dynamic_construction_detected
    )
    sql_prepare_call_detected = bool(_SQL_PREPARE_CALL_RE.search(source_code))
    sql_prepare_statement_detected = bool(_SQL_PREPARE_STATEMENT_RE.search(source_code))
    sql_callable_statement_detected = bool(_SQL_CALLABLE_STATEMENT_RE.search(source_code))
    sql_execution_detected = sql_prepare_call_detected or sql_prepare_statement_detected or any(
        pattern.search(source_code) for pattern in _SQL_EXECUTE_CALL_PATTERNS
    )
    sql_dynamic_query_detected = bool(
        sql_untrusted_input_detected and sql_execution_detected and dynamic_construction_detected
    )

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
        "sql_dynamic_query_detected": sql_dynamic_query_detected,
    }


def analyze_crypto_indicators(source_code: str) -> Dict[str, bool]:
    return analyze_policy_indicators(source_code)
