from __future__ import annotations

from codegraph.policy.analysis.command import CommandFlowAnalyzer
from codegraph.policy.analysis.crypto import CryptoIndicatorAnalyzer
from codegraph.policy.analysis.injection import (
    LDAPSafetyAnalyzer,
    PathSafetyAnalyzer,
    SQLSafetyAnalyzer,
    XPathSafetyAnalyzer,
)
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
from codegraph.policy.source_analysis_sanitizer import strip_java_lexical_noise

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


class PolicyIndicatorAnalyzer:
    def __init__(self) -> None:
        self._crypto = CryptoIndicatorAnalyzer()
        self._path_safety = PathSafetyAnalyzer()
        self._command_flow = CommandFlowAnalyzer()
        self._ldap_safety = LDAPSafetyAnalyzer()
        self._xpath_safety = XPathSafetyAnalyzer()
        self._sql_safety = SQLSafetyAnalyzer()

    @staticmethod
    def empty_flags() -> dict[str, bool]:
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

    def analyze(self, source_code: str) -> dict[str, bool]:
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
