from __future__ import annotations

from typing import Dict

from codegraph.policy.analysis.patterns import (
    CMDI_PATTERNS,
    LDAP_PATTERNS,
    PATH_LDAP_UNTRUSTED_INPUT_PATTERNS,
    PATH_TRAVERSAL_PATTERNS,
    SQL_CALLABLE_STATEMENT_RE,
    SQL_EXECUTE_CALL_PATTERNS,
    SQL_PREPARE_CALL_RE,
    SQL_PREPARE_STATEMENT_RE,
    UNTRUSTED_INPUT_PATTERNS,
    XPATH_PATTERNS,
)

__all__ = [
    "CMDI_PATTERNS",
    "DEFAULT_POLICY_ANALYZER",
    "LDAP_PATTERNS",
    "PATH_LDAP_UNTRUSTED_INPUT_PATTERNS",
    "PATH_TRAVERSAL_PATTERNS",
    "PolicyIndicatorAnalyzer",
    "SQL_CALLABLE_STATEMENT_RE",
    "SQL_EXECUTE_CALL_PATTERNS",
    "SQL_PREPARE_CALL_RE",
    "SQL_PREPARE_STATEMENT_RE",
    "UNTRUSTED_INPUT_PATTERNS",
    "XPATH_PATTERNS",
    "strip_java_lexical_noise",
]


def strip_java_lexical_noise(source: str, *, strip_string_literals: bool = True) -> str:
    """Return ``source`` with lexically-inactive content blanked.

    Two modes are supported via ``strip_string_literals``:

    * ``True`` (default) — comments, char literals, string literals,
      and text-block contents are blanked. Produces the *substring-safe*
      view used by the OPA/Rego rules that perform naive
      ``contains(...)`` matching on ``input.source_code``. A token
      mentioned only inside a comment or quoted string cannot trigger a
      substring rule on this view.
    * ``False`` — only comments are blanked; the contents of string
      literals, char literals, and text blocks are preserved. Produces
      the *active-code* view used by the Python regex pre-analysis
      layer (``codegraph.policy.analysis``), whose patterns are
      structurally anchored and intentionally inspect the contents of
      string-literal arguments (for example, the ``"MD5"`` inside
      ``MessageDigest.getInstance("MD5")``). Preserving literals here
      keeps algorithm-name detection working post-F10.

    In both modes, newline characters are emitted verbatim so that
    line numbers, line counts, and per-line character offsets in the
    returned string match the input exactly — the citation-grounding
    contract for evidence cards.

    The state machine recognises:

    * line comments (``// ... \\n`` or ``... \\r``, JLS §3.4)
    * block comments and javadoc (``/* ... */``, ``/** ... */``)
    * char literals (``'c'`` with ``\\'`` escape)
    * string literals (``"..."`` with ``\\"`` escape)
    * text blocks (``\"\"\" ... \"\"\"`` — Java 13+)

    Design note — F10 unification.
    Before F10, comment and literal stripping was applied *ad hoc*: a
    handful of Python analyzers (notably the INSECURE_RANDOM checks in
    ``codegraph.policy.analysis.crypto``) called ``SourceSanitizer`` to
    strip comments and string literals before pattern matching, while
    the OPA/Rego rules and most other Python rules operated on raw
    source and were therefore vulnerable to lexical-noise false
    positives. F10 unifies this pattern across *every* rule path:
    Rego rules receive the substring-safe view, the Python regex
    layer receives the active-code view, and the LLM/UI receive the
    raw view. This means the contract is the same for all rules; there
    are no longer selective callers of an opt-in sanitizer.

    Known limitations (acceptable for the OWASP Benchmark + JHipster /
    PetClinic real-world corpora):

    * Unicode escapes of the form ``\\uXXXX`` are not pre-processed.
      Java's compiler resolves them before tokenisation, so technically
      a quote written as ``\\u0022`` would still toggle string state
      in real Java. We treat ``\\uXXXX`` as ordinary characters; this
      mismatches the language spec only on adversarially obfuscated
      sources, which are out of scope.
    * Nested block comments are not a Java construct (the compiler
      terminates at the first ``*/``); we match that behaviour.
    """
    src_len = len(source)
    out: list[str] = []
    i = 0

    state = "code"
    escaped = False

    while i < src_len:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < src_len else ""
        nxt2 = source[i + 2] if i + 2 < src_len else ""

        if state == "code":
            if ch == "/" and nxt == "/":
                out.append("  ")
                state = "line_comment"
                i += 2
                continue
            if ch == "/" and nxt == "*":
                out.append("  ")
                state = "block_comment"
                i += 2
                continue
            if ch == '"' and nxt == '"' and nxt2 == '"':
                out.append("   " if strip_string_literals else '"""')
                state = "text_block"
                escaped = False
                i += 3
                continue
            if ch == '"':
                out.append(" " if strip_string_literals else '"')
                state = "string"
                escaped = False
                i += 1
                continue
            if ch == "'":
                out.append(" " if strip_string_literals else "'")
                state = "char"
                escaped = False
                i += 1
                continue
            out.append(ch)
            i += 1
            continue

        if state == "line_comment":
            # JLS §3.4: LF, CR, or CRLF terminate a line. Treat both LF
            # and CR as comment terminators; preserve them verbatim so
            # downstream line-counting stays correct for either style.
            if ch == "\n" or ch == "\r":
                out.append(ch)
                state = "code"
                i += 1
                continue
            out.append(" ")
            i += 1
            continue

        if state == "block_comment":
            if ch == "*" and nxt == "/":
                out.append("  ")
                state = "code"
                i += 2
                continue
            out.append("\n" if ch == "\n" else " ")
            i += 1
            continue

        if state == "string":
            if escaped:
                out.append(" " if strip_string_literals else ch)
                escaped = False
                i += 1
                continue
            if ch == "\\":
                out.append(" " if strip_string_literals else "\\")
                escaped = True
                i += 1
                continue
            if ch == '"':
                out.append(" " if strip_string_literals else '"')
                state = "code"
                i += 1
                continue
            # An unescaped JLS §3.4 line terminator (LF / CR / CRLF) is a
            # syntax error in standard string literals; close the literal
            # defensively so a malformed source can't silently consume
            # the rest of the file.
            if ch == "\n" or ch == "\r":
                out.append(ch)
                state = "code"
                i += 1
                continue
            out.append(" " if strip_string_literals else ch)
            i += 1
            continue

        if state == "char":
            if escaped:
                out.append(" " if strip_string_literals else ch)
                escaped = False
                i += 1
                continue
            if ch == "\\":
                out.append(" " if strip_string_literals else "\\")
                escaped = True
                i += 1
                continue
            if ch == "'":
                out.append(" " if strip_string_literals else "'")
                state = "code"
                i += 1
                continue
            # JLS §3.4: char literals also cannot span line terminators.
            if ch == "\n" or ch == "\r":
                out.append(ch)
                state = "code"
                i += 1
                continue
            out.append(" " if strip_string_literals else ch)
            i += 1
            continue

        # state == "text_block"
        # The closing delimiter is exactly three consecutive double
        # quotes. Inside a text block, single and double quotes (not
        # preceded by the escape \\") do NOT close the block unless
        # three appear in a row.
        if ch == "\\" and not escaped:
            out.append(" " if strip_string_literals else "\\")
            escaped = True
            i += 1
            continue
        if escaped:
            if ch == "\n":
                out.append("\n")
            else:
                out.append(" " if strip_string_literals else ch)
            escaped = False
            i += 1
            continue
        if ch == '"' and nxt == '"' and nxt2 == '"':
            out.append("   " if strip_string_literals else '"""')
            state = "code"
            i += 3
            continue
        if ch == "\n":
            out.append("\n")
        else:
            out.append(" " if strip_string_literals else ch)
        i += 1

    return "".join(out)


class PolicyIndicatorAnalyzer:
    def __init__(self) -> None:
        from codegraph.policy.analysis.command import CommandFlowAnalyzer
        from codegraph.policy.analysis.crypto import CryptoIndicatorAnalyzer
        from codegraph.policy.analysis.injection import (
            LDAPSafetyAnalyzer,
            PathSafetyAnalyzer,
            SQLSafetyAnalyzer,
            XPathSafetyAnalyzer,
        )

        self._crypto = CryptoIndicatorAnalyzer()
        self._path_safety = PathSafetyAnalyzer()
        self._command_flow = CommandFlowAnalyzer()
        self._ldap_safety = LDAPSafetyAnalyzer()
        self._xpath_safety = XPathSafetyAnalyzer()
        self._sql_safety = SQLSafetyAnalyzer()

    @staticmethod
    def empty_flags() -> Dict[str, bool]:
        return {
            "md5_literal": False,
            "md5_variable": False,
            "md5_detected": False,
            "weak_hash_literal": False,
            "weak_hash_variable": False,
            "weak_hash_detected": False,
            "weak_cipher_literal": False,
            "weak_cipher_detected": False,
            "insecure_random_detected": False,
            "sha1prng_detected": False,
            "path_traversal_detected": False,
            "path_safe_constant_detected": False,
            "path_sink_uses_tainted_input": False,
            "path_sink_uses_safe_constant": False,
            "path_sink_uses_safe_resource_helper": False,
            "command_exec_string_tainted": False,
            "command_exec_args_tainted": False,
            "command_env_only_tainted": False,
            "command_injection_detected": False,
            "ldap_injection_detected": False,
            "ldap_filter_uses_tainted_input": False,
            "ldap_filter_uses_safe_constant": False,
            "xpath_injection_detected": False,
            "xpath_query_uses_tainted_input": False,
            "xpath_query_uses_safe_constant": False,
            "sql_query_uses_tainted_input": False,
            "sql_query_uses_safe_constant": False,
            "sql_prepare_call_detected": False,
            "sql_callable_statement_detected": False,
            "sql_dynamic_query_detected": False,
        }

    def analyze(self, source_code: str) -> Dict[str, bool]:
        if not source_code:
            return self.empty_flags()

        path_ldap_untrusted_input_detected = any(
            pattern.search(source_code) for pattern in PATH_LDAP_UNTRUSTED_INPUT_PATTERNS
        )
        crypto = self._crypto.analyze(source_code)

        path_analysis = self._path_safety.analyze(source_code)
        path_safe_constant_detected = path_analysis.path_sink_uses_safe_constant
        path_traversal_detected = path_ldap_untrusted_input_detected and path_analysis.path_traversal_detected
        command_analysis = self._command_flow.analyze(source_code)
        ldap_analysis = self._ldap_safety.analyze(source_code)
        xpath_analysis = self._xpath_safety.analyze(source_code)
        sql_analysis = self._sql_safety.analyze(source_code)
        command_exec_string_tainted = command_analysis.command_exec_string_tainted
        command_exec_args_tainted = command_analysis.command_exec_args_tainted
        command_env_only_tainted = command_analysis.command_env_only_tainted
        command_injection_detected = command_exec_string_tainted or command_exec_args_tainted
        ldap_injection_detected = path_ldap_untrusted_input_detected and ldap_analysis.ldap_injection_detected
        xpath_injection_detected = xpath_analysis.xpath_injection_detected
        sql_prepare_call_detected = bool(SQL_PREPARE_CALL_RE.search(source_code))
        sql_prepare_statement_detected = bool(SQL_PREPARE_STATEMENT_RE.search(source_code))
        sql_callable_statement_detected = bool(SQL_CALLABLE_STATEMENT_RE.search(source_code))
        sql_execution_detected = (
            sql_prepare_call_detected
            or sql_prepare_statement_detected
            or any(pattern.search(source_code) for pattern in SQL_EXECUTE_CALL_PATTERNS)
        )
        sql_dynamic_query_detected = bool(sql_execution_detected and sql_analysis.sql_dynamic_query_detected)

        md5_detected = crypto.md5_literal or crypto.md5_variable
        weak_hash_detected = crypto.weak_hash_literal or crypto.weak_hash_variable
        weak_cipher_detected = crypto.weak_cipher_literal
        return {
            "md5_literal": crypto.md5_literal,
            "md5_variable": crypto.md5_variable,
            "md5_detected": md5_detected,
            "weak_hash_literal": crypto.weak_hash_literal,
            "weak_hash_variable": crypto.weak_hash_variable,
            "weak_hash_detected": weak_hash_detected,
            "weak_cipher_literal": crypto.weak_cipher_literal,
            "weak_cipher_detected": weak_cipher_detected,
            "insecure_random_detected": crypto.insecure_random_detected,
            "sha1prng_detected": crypto.sha1prng_detected,
            "path_traversal_detected": path_traversal_detected,
            "path_safe_constant_detected": path_safe_constant_detected,
            "path_sink_uses_tainted_input": path_analysis.path_sink_uses_tainted_input,
            "path_sink_uses_safe_constant": path_analysis.path_sink_uses_safe_constant,
            "path_sink_uses_safe_resource_helper": path_analysis.path_sink_uses_safe_resource_helper,
            "command_exec_string_tainted": command_exec_string_tainted,
            "command_exec_args_tainted": command_exec_args_tainted,
            "command_env_only_tainted": command_env_only_tainted,
            "command_injection_detected": command_injection_detected,
            "ldap_injection_detected": ldap_injection_detected,
            "ldap_filter_uses_tainted_input": ldap_analysis.ldap_filter_uses_tainted_input,
            "ldap_filter_uses_safe_constant": ldap_analysis.ldap_filter_uses_safe_constant,
            "xpath_injection_detected": xpath_injection_detected,
            "xpath_query_uses_tainted_input": xpath_analysis.xpath_query_uses_tainted_input,
            "xpath_query_uses_safe_constant": xpath_analysis.xpath_query_uses_safe_constant,
            "sql_query_uses_tainted_input": sql_analysis.sql_query_uses_tainted_input,
            "sql_query_uses_safe_constant": sql_analysis.sql_query_uses_safe_constant,
            "sql_prepare_call_detected": sql_prepare_call_detected,
            "sql_callable_statement_detected": sql_callable_statement_detected,
            "sql_dynamic_query_detected": sql_dynamic_query_detected,
        }


DEFAULT_POLICY_ANALYZER = PolicyIndicatorAnalyzer()
