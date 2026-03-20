from __future__ import annotations

from dataclasses import dataclass
import re

from codegraph.policy.analysis.state import (
    AssignmentState,
    AssignmentStateAnalyzer,
    SIMPLE_ASSIGNMENT_RE,
)
from codegraph.policy.source_analysis_core import (
    APPEND_CALL_RE,
    DIRECT_LDAP_UNTRUSTED_PATTERNS,
    DIRECT_PATH_UNTRUSTED_PATTERNS,
    DIRECT_SQL_UNTRUSTED_PATTERNS,
    DIRECT_XPATH_UNTRUSTED_PATTERNS,
    LDAP_FILTER_VARIABLE_PATTERNS,
    LDAP_PATTERNS,
    PATH_DYNAMIC_ARGUMENT_PATTERNS,
    PATH_DYNAMIC_CONSTRUCTION_PATTERNS,
    PATH_LDAP_UNTRUSTED_INPUT_PATTERNS,
    PATH_SAFE_RESOURCE_PATTERNS,
    PATH_SINK_VARIABLE_PATTERNS,
    PATH_TRAVERSAL_PATTERNS,
    SQL_EXECUTE_CALL_PATTERNS,
    SQL_PREPARE_CALL_RE,
    SQL_PREPARE_STATEMENT_RE,
    SQL_SINK_VARIABLE_PATTERNS,
    SQL_UNTRUSTED_INPUT_PATTERNS,
    STRING_BUILDER_RE,
    STRING_CONCAT_PATTERNS,
    XPATH_PATTERNS,
    XPATH_SINK_VARIABLE_PATTERNS,
)


@dataclass(frozen=True)
class PathAnalysis:
    path_sink_uses_tainted_input: bool
    path_sink_uses_safe_constant: bool
    path_sink_uses_safe_resource_helper: bool
    path_traversal_detected: bool


@dataclass(frozen=True)
class XPathAnalysis:
    xpath_query_uses_tainted_input: bool
    xpath_query_uses_safe_constant: bool
    xpath_injection_detected: bool


@dataclass(frozen=True)
class LDAPAnalysis:
    ldap_filter_uses_tainted_input: bool
    ldap_filter_uses_safe_constant: bool
    ldap_injection_detected: bool


@dataclass(frozen=True)
class SQLAnalysis:
    sql_query_uses_tainted_input: bool
    sql_query_uses_safe_constant: bool
    sql_dynamic_query_detected: bool


def _sink_vars(source_code: str, patterns: tuple[re.Pattern[str], ...]) -> set[str]:
    sink_vars: set[str] = set()
    for pattern in patterns:
        for match in pattern.finditer(source_code):
            sink_vars.add(match.group(1))
    return sink_vars


def _sink_uses_safe_constant(
    source_code: str,
    *,
    state: AssignmentState,
    sink_vars: set[str],
    assignment_analyzer: AssignmentStateAnalyzer,
) -> bool:
    if not sink_vars:
        return False
    if sink_vars & set(state.string_constants):
        return True
    for match in SIMPLE_ASSIGNMENT_RE.finditer(source_code):
        var = match.group(1)
        if var not in sink_vars:
            continue
        referenced = assignment_analyzer.referenced_variables(match.group(2))
        if referenced & state.tainted_vars:
            continue
        if referenced & set(state.string_constants):
            return True
    return False


class PathSafetyAnalyzer:
    def __init__(self) -> None:
        self._assignment_analyzer = AssignmentStateAnalyzer(PATH_LDAP_UNTRUSTED_INPUT_PATTERNS)

    def analyze(self, source_code: str) -> PathAnalysis:
        state = self._assignment_analyzer.analyze(source_code)
        sink_vars = _sink_vars(source_code, PATH_SINK_VARIABLE_PATTERNS)
        path_sink_uses_safe_constant = _sink_uses_safe_constant(
            source_code,
            state=state,
            sink_vars=sink_vars,
            assignment_analyzer=self._assignment_analyzer,
        )
        path_sink_uses_safe_resource_helper = any(pattern.search(source_code) for pattern in PATH_SAFE_RESOURCE_PATTERNS)
        path_sink_uses_tainted_input = self._sink_uses_tainted_input(source_code, state, sink_vars)
        compatibility_path_signal = self._compatibility_path_signal(source_code, sink_vars)
        path_traversal_detected = (
            any(pattern.search(source_code) for pattern in PATH_TRAVERSAL_PATTERNS)
            and (path_sink_uses_tainted_input or compatibility_path_signal)
            and not path_sink_uses_safe_constant
            and not path_sink_uses_safe_resource_helper
        )
        return PathAnalysis(
            path_sink_uses_tainted_input=path_sink_uses_tainted_input,
            path_sink_uses_safe_constant=path_sink_uses_safe_constant,
            path_sink_uses_safe_resource_helper=path_sink_uses_safe_resource_helper,
            path_traversal_detected=path_traversal_detected,
        )

    def safe_constant_override_detected(self, source_code: str) -> bool:
        return self.analyze(source_code).path_sink_uses_safe_constant

    def sink_references_tainted_data(self, source_code: str) -> bool:
        return self.analyze(source_code).path_sink_uses_tainted_input

    @staticmethod
    def _sink_uses_tainted_input(source_code: str, state: AssignmentState, sink_vars: set[str]) -> bool:
        if any(pattern.search(source_code) for pattern in DIRECT_PATH_UNTRUSTED_PATTERNS):
            return True
        for sink_var in sink_vars:
            if sink_var in state.tainted_vars:
                return True
        return False

    @staticmethod
    def _compatibility_path_signal(source_code: str, sink_vars: set[str]) -> bool:
        if any(pattern.search(source_code) for pattern in DIRECT_PATH_UNTRUSTED_PATTERNS):
            return True
        has_dynamic_sink_shape = any(pattern.search(source_code) for pattern in PATH_DYNAMIC_ARGUMENT_PATTERNS)
        has_dynamic_path_construction = any(pattern.search(source_code) for pattern in PATH_DYNAMIC_CONSTRUCTION_PATTERNS)
        return bool(sink_vars) and (has_dynamic_sink_shape or has_dynamic_path_construction)


class XPathSafetyAnalyzer:
    def __init__(self) -> None:
        self._assignment_analyzer = AssignmentStateAnalyzer(PATH_LDAP_UNTRUSTED_INPUT_PATTERNS)

    def analyze(self, source_code: str) -> XPathAnalysis:
        state = self._assignment_analyzer.analyze(source_code)
        sink_vars = _sink_vars(source_code, XPATH_SINK_VARIABLE_PATTERNS)
        xpath_query_uses_safe_constant = _sink_uses_safe_constant(
            source_code,
            state=state,
            sink_vars=sink_vars,
            assignment_analyzer=self._assignment_analyzer,
        )
        xpath_query_uses_tainted_input = self._sink_uses_tainted_input(source_code, state, sink_vars)
        compatibility_xpath_signal = self._compatibility_xpath_signal(source_code)
        xpath_injection_detected = (
            (xpath_query_uses_tainted_input or compatibility_xpath_signal) and not xpath_query_uses_safe_constant
        )
        return XPathAnalysis(
            xpath_query_uses_tainted_input=xpath_query_uses_tainted_input,
            xpath_query_uses_safe_constant=xpath_query_uses_safe_constant,
            xpath_injection_detected=xpath_injection_detected,
        )

    @staticmethod
    def _sink_uses_tainted_input(source_code: str, state: AssignmentState, sink_vars: set[str]) -> bool:
        if any(pattern.search(source_code) for pattern in DIRECT_XPATH_UNTRUSTED_PATTERNS):
            return True
        return any(sink_var in state.tainted_vars for sink_var in sink_vars)

    @staticmethod
    def _compatibility_xpath_signal(source_code: str) -> bool:
        if any(pattern.search(source_code) for pattern in DIRECT_XPATH_UNTRUSTED_PATTERNS):
            return True
        has_dynamic_construction = bool(
            any(pattern.search(source_code) for pattern in STRING_CONCAT_PATTERNS)
            or (STRING_BUILDER_RE.search(source_code) and APPEND_CALL_RE.search(source_code))
        )
        return bool(all(pattern.search(source_code) for pattern in XPATH_PATTERNS) and has_dynamic_construction)


class LDAPSafetyAnalyzer:
    def __init__(self) -> None:
        self._assignment_analyzer = AssignmentStateAnalyzer(PATH_LDAP_UNTRUSTED_INPUT_PATTERNS)

    def analyze(self, source_code: str) -> LDAPAnalysis:
        state = self._assignment_analyzer.analyze(source_code)
        sink_vars = _sink_vars(source_code, LDAP_FILTER_VARIABLE_PATTERNS)
        ldap_filter_uses_safe_constant = _sink_uses_safe_constant(
            source_code,
            state=state,
            sink_vars=sink_vars,
            assignment_analyzer=self._assignment_analyzer,
        )
        ldap_filter_uses_tainted_input = self._sink_uses_tainted_input(source_code, state, sink_vars)
        compatibility_ldap_signal = self._compatibility_ldap_signal(source_code, sink_vars)
        ldap_injection_detected = (
            (ldap_filter_uses_tainted_input or compatibility_ldap_signal) and not ldap_filter_uses_safe_constant
        )
        return LDAPAnalysis(
            ldap_filter_uses_tainted_input=ldap_filter_uses_tainted_input,
            ldap_filter_uses_safe_constant=ldap_filter_uses_safe_constant,
            ldap_injection_detected=ldap_injection_detected,
        )

    @staticmethod
    def _sink_uses_tainted_input(source_code: str, state: AssignmentState, sink_vars: set[str]) -> bool:
        if any(pattern.search(source_code) for pattern in DIRECT_LDAP_UNTRUSTED_PATTERNS):
            return True
        return any(sink_var in state.tainted_vars for sink_var in sink_vars)

    @staticmethod
    def _compatibility_ldap_signal(source_code: str, sink_vars: set[str]) -> bool:
        if any(pattern.search(source_code) for pattern in DIRECT_LDAP_UNTRUSTED_PATTERNS):
            return True
        has_dynamic_construction = bool(
            any(pattern.search(source_code) for pattern in STRING_CONCAT_PATTERNS)
            or (STRING_BUILDER_RE.search(source_code) and APPEND_CALL_RE.search(source_code))
        )
        has_ldap_context = any(pattern.search(source_code) for pattern in LDAP_PATTERNS[:2])
        has_ldap_search = bool(LDAP_PATTERNS[2].search(source_code))
        return bool(has_ldap_context and has_ldap_search and sink_vars and has_dynamic_construction)


class SQLSafetyAnalyzer:
    def __init__(self) -> None:
        self._assignment_analyzer = AssignmentStateAnalyzer(SQL_UNTRUSTED_INPUT_PATTERNS)

    def analyze(self, source_code: str) -> SQLAnalysis:
        state = self._assignment_analyzer.analyze(source_code)
        sink_vars = _sink_vars(source_code, SQL_SINK_VARIABLE_PATTERNS)
        sql_query_uses_safe_constant = _sink_uses_safe_constant(
            source_code,
            state=state,
            sink_vars=sink_vars,
            assignment_analyzer=self._assignment_analyzer,
        )
        sql_query_uses_tainted_input = self._sink_uses_tainted_input(source_code, state, sink_vars)
        compatibility_sql_signal = self._compatibility_sql_signal(source_code)
        sql_dynamic_query_detected = (
            (sql_query_uses_tainted_input or compatibility_sql_signal) and not sql_query_uses_safe_constant
        )
        return SQLAnalysis(
            sql_query_uses_tainted_input=sql_query_uses_tainted_input,
            sql_query_uses_safe_constant=sql_query_uses_safe_constant,
            sql_dynamic_query_detected=sql_dynamic_query_detected,
        )

    @staticmethod
    def _sink_uses_tainted_input(source_code: str, state: AssignmentState, sink_vars: set[str]) -> bool:
        if any(pattern.search(source_code) for pattern in DIRECT_SQL_UNTRUSTED_PATTERNS):
            return True
        return any(sink_var in state.tainted_vars for sink_var in sink_vars)

    @staticmethod
    def _compatibility_sql_signal(source_code: str) -> bool:
        if any(pattern.search(source_code) for pattern in DIRECT_SQL_UNTRUSTED_PATTERNS):
            return True
        has_dynamic_construction = bool(
            any(pattern.search(source_code) for pattern in STRING_CONCAT_PATTERNS)
            or (STRING_BUILDER_RE.search(source_code) and APPEND_CALL_RE.search(source_code))
        )
        has_sql_keyword = any(keyword in source_code.lower() for keyword in ("select ", "insert ", "update ", "delete "))
        has_sql_sink = bool(
            any(pattern.search(source_code) for pattern in SQL_EXECUTE_CALL_PATTERNS)
            or SQL_PREPARE_CALL_RE.search(source_code)
            or SQL_PREPARE_STATEMENT_RE.search(source_code)
        )
        return has_dynamic_construction and has_sql_keyword and has_sql_sink
