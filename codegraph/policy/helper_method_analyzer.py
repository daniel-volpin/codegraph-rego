from __future__ import annotations

import re
from dataclasses import dataclass

from codegraph.policy.analysis.conditional import resolve_list_get_sequence
from codegraph.policy.analysis.state import AssignmentStateAnalyzer
from codegraph.policy.helper_summary_patterns import (
    CALL_ASSIGNMENT_WITH_ARGS_RE,
    LIST_ADD_RE,
    LIST_GET_ASSIGNMENT_RE,
    LIST_REMOVE_RE,
    MAP_GET_ASSIGNMENT_RE,
    MAP_GET_LITERAL_RE,
    MAP_PUT_LITERAL_RE,
    MAP_PUT_VALUE_RE,
    METHOD_DECL_RE,
    RETURN_RE,
    STRING_LITERAL_FULL_RE,
)
from codegraph.policy.source_analysis_core import UNTRUSTED_INPUT_PATTERNS


@dataclass(frozen=True)
class HelperReturnSummary:
    returns_constant_string: bool
    propagates_tainted_input: bool


class HelperCollectionResolver:
    def resolve(
        self,
        source_code: str,
        *,
        assignment_analyzer: AssignmentStateAnalyzer,
        initial_tainted_vars: set[str],
    ) -> str:
        resolved = source_code
        for _ in range(3):
            state = assignment_analyzer.analyze(resolved, initial_tainted_vars=initial_tainted_vars)
            updated = self._replace_map_gets(resolved, assignment_analyzer, state)
            updated = self._replace_list_gets(updated, assignment_analyzer, state)
            if updated == resolved:
                return updated
            resolved = updated
        return resolved

    def _replace_map_gets(self, source_code: str, assignment_analyzer: AssignmentStateAnalyzer, state) -> str:
        entries: dict[str, dict[str, str]] = {}
        for map_name, key, raw_value in MAP_PUT_VALUE_RE.findall(source_code):
            resolved = self._resolve_expr(raw_value.strip(), assignment_analyzer, state)
            if resolved is not None:
                entries.setdefault(map_name, {})[key] = resolved

        def _replace(match: re.Match[str]) -> str:
            target_var, map_name, key = match.groups()
            resolved = entries.get(map_name, {}).get(key)
            if resolved is None:
                return match.group(0)
            return f"{target_var} = {resolved};"

        return MAP_GET_ASSIGNMENT_RE.sub(_replace, source_code)

    def _replace_list_gets(self, source_code: str, assignment_analyzer: AssignmentStateAnalyzer, state) -> str:
        return resolve_list_get_sequence(
            source_code,
            LIST_ADD_RE,
            LIST_REMOVE_RE,
            LIST_GET_ASSIGNMENT_RE,
            lambda expr: self._resolve_expr(expr, assignment_analyzer, state),
        )

    @staticmethod
    def _resolve_expr(expr: str, assignment_analyzer: AssignmentStateAnalyzer, state) -> str | None:
        literal_match = STRING_LITERAL_FULL_RE.match(expr)
        if literal_match:
            return expr
        if expr in state.string_constants:
            return f'"{state.string_constants[expr]}"'
        if expr in state.tainted_vars:
            return expr
        referenced = assignment_analyzer.referenced_variables(expr)
        if referenced and referenced <= state.tainted_vars:
            return expr
        return None


class HelperMethodAnalyzer:
    def __init__(self) -> None:
        self._assignment_analyzer = AssignmentStateAnalyzer(UNTRUSTED_INPUT_PATTERNS)
        self._collection_resolver = HelperCollectionResolver()

    def summarize(self, source_code: str) -> HelperReturnSummary:
        if not source_code:
            return HelperReturnSummary(returns_constant_string=False, propagates_tainted_input=False)
        initial_tainted = self._parameter_names(source_code)
        resolved_source = self._collection_resolver.resolve(
            source_code,
            assignment_analyzer=self._assignment_analyzer,
            initial_tainted_vars=initial_tainted,
        )
        state = self._assignment_analyzer.analyze(resolved_source, initial_tainted_vars=initial_tainted)
        map_constants = self._map_string_constants(source_code)
        returns_constant = False
        propagates_taint = False
        for match in RETURN_RE.finditer(resolved_source):
            expr = match.group(1).strip()
            if expr in state.string_constants:
                returns_constant = True
            elif expr.startswith('"') and expr.endswith('"'):
                returns_constant = True
            elif expr in state.tainted_vars:
                propagates_taint = True
            else:
                map_match = MAP_GET_LITERAL_RE.search(expr)
                if (
                    map_match
                    and map_match.group(1) in map_constants
                    and map_match.group(2) in map_constants[map_match.group(1)]
                ):
                    returns_constant = True
                elif self._assigned_from_safe_call(expr, resolved_source, state):
                    returns_constant = True
                elif self._assigned_from_tainted_call(expr, resolved_source, state):
                    propagates_taint = True
                elif self._assignment_analyzer.referenced_variables(expr) & state.tainted_vars:
                    propagates_taint = True
        return HelperReturnSummary(
            returns_constant_string=returns_constant,
            propagates_tainted_input=propagates_taint,
        )

    def _assigned_from_safe_call(self, expr: str, source_code: str, state) -> bool:
        for assigned_var, _method_name, raw_args in CALL_ASSIGNMENT_WITH_ARGS_RE.findall(source_code):
            if assigned_var != expr:
                continue
            arg_refs = self._assignment_analyzer.referenced_variables(raw_args)
            if arg_refs & state.tainted_vars:
                continue
            if STRING_LITERAL_FULL_RE.match(raw_args.strip()):
                return True
            if arg_refs and arg_refs <= set(state.string_constants):
                return True
        return False

    def _assigned_from_tainted_call(self, expr: str, source_code: str, state) -> bool:
        for assigned_var, _method_name, raw_args in CALL_ASSIGNMENT_WITH_ARGS_RE.findall(source_code):
            if assigned_var != expr:
                continue
            if any(pattern.search(raw_args) for pattern in UNTRUSTED_INPUT_PATTERNS):
                return True
            if self._assignment_analyzer.referenced_variables(raw_args) & state.tainted_vars:
                return True
        return False

    @staticmethod
    def _parameter_names(source_code: str) -> set[str]:
        match = METHOD_DECL_RE.search(source_code)
        if not match:
            return set()
        names: set[str] = set()
        for raw_param in match.group(1).split(","):
            param = raw_param.strip()
            if not param:
                continue
            parts = param.split()
            if len(parts) < 2:
                continue
            type_name = " ".join(parts[:-1])
            name = parts[-1]
            if "HttpServletRequest" in type_name or "HttpServletResponse" in type_name:
                continue
            names.add(name)
        return names

    @staticmethod
    def _map_string_constants(source_code: str) -> dict[str, dict[str, str]]:
        values: dict[str, dict[str, str]] = {}
        for map_name, key, value in MAP_PUT_LITERAL_RE.findall(source_code):
            values.setdefault(map_name, {})[key] = value
        return values
