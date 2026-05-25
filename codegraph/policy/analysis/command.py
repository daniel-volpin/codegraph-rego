from __future__ import annotations

from dataclasses import dataclass
from typing import Dict

from codegraph.policy.analysis.patterns import (
    BUILDER_TOSTRING_RE,
    COMMAND_APPEND_RE,
    COMMAND_ARRAY_ASSIGNMENT_RE,
    COMMAND_EXEC_MULTI_ARG_RE,
    COMMAND_EXEC_SINGLE_ARG_RE,
    COMMAND_EXPR_USAGE_RE,
    COMMAND_LIST_ADD_RE,
    COMMAND_LIST_USAGE_RE,
    COMMAND_UNTRUSTED_INPUT_PATTERNS,
)
from codegraph.policy.analysis.state import AssignmentState, AssignmentStateAnalyzer


@dataclass(frozen=True)
class CommandAnalysis:
    command_exec_string_tainted: bool
    command_exec_args_tainted: bool
    command_env_only_tainted: bool


class CommandFlowAnalyzer:
    def __init__(self) -> None:
        self._assignment_analyzer = AssignmentStateAnalyzer(COMMAND_UNTRUSTED_INPUT_PATTERNS)

    def analyze(self, source_code: str) -> CommandAnalysis:
        state = self._assignment_analyzer.analyze(source_code)
        list_taint = self._list_taint(source_code, state)
        array_taint = self._array_taint(source_code, state)
        builder_taint = self._builder_taint(source_code, state)
        payload_lists = self._payload_lists(source_code)

        exec_string_tainted = False
        exec_args_tainted = False
        env_only_tainted = False
        multi_spans: list[tuple[int, int]] = []

        for match in COMMAND_EXEC_MULTI_ARG_RE.finditer(source_code):
            multi_spans.append(match.span())
            first = match.group("first").strip()
            second = match.group("second")
            first_tainted, first_is_args = self._command_expr_tainted(
                first,
                state=state,
                list_taint=list_taint,
                array_taint=array_taint,
                builder_taint=builder_taint,
            )
            second_tainted = array_taint.get(second, False) or second in state.tainted_vars
            if first_tainted:
                if first_is_args:
                    exec_args_tainted = True
                else:
                    exec_string_tainted = True
            elif second_tainted:
                env_only_tainted = True

        for match in COMMAND_EXEC_SINGLE_ARG_RE.finditer(source_code):
            if any(start <= match.start() and match.end() <= end for start, end in multi_spans):
                continue
            first = match.group("first").strip()
            if "," in first:
                continue
            first_tainted, first_is_args = self._command_expr_tainted(
                first,
                state=state,
                list_taint=list_taint,
                array_taint=array_taint,
                builder_taint=builder_taint,
            )
            if first_tainted:
                if first_is_args:
                    exec_args_tainted = True
                else:
                    exec_string_tainted = True

        for match in COMMAND_EXPR_USAGE_RE.finditer(source_code):
            expr = (match.group("ctor") or match.group("call") or "").strip()
            if not expr:
                continue
            if expr in payload_lists:
                if list_taint.get(expr, False):
                    exec_args_tainted = True
                continue
            tainted, is_args = self._command_expr_tainted(
                expr,
                state=state,
                list_taint=list_taint,
                array_taint=array_taint,
                builder_taint=builder_taint,
            )
            if tainted:
                if is_args:
                    exec_args_tainted = True
                else:
                    exec_string_tainted = True

        return CommandAnalysis(
            command_exec_string_tainted=exec_string_tainted,
            command_exec_args_tainted=exec_args_tainted,
            command_env_only_tainted=env_only_tainted,
        )

    @staticmethod
    def _payload_lists(source_code: str) -> set[str]:
        list_variables = {list_name for list_name, _expr in COMMAND_LIST_ADD_RE.findall(source_code)}
        return {
            candidate
            for groups in COMMAND_LIST_USAGE_RE.findall(source_code)
            for candidate in groups
            if candidate and candidate in list_variables
        }

    def _command_expr_tainted(
        self,
        expr: str,
        *,
        state: AssignmentState,
        list_taint: Dict[str, bool],
        array_taint: Dict[str, bool],
        builder_taint: Dict[str, bool],
    ) -> tuple[bool, bool]:
        normalized = expr.strip()
        if not normalized:
            return False, False
        if any(pattern.search(normalized) for pattern in COMMAND_UNTRUSTED_INPUT_PATTERNS):
            return True, False
        if normalized in state.string_constants:
            return False, False
        if normalized in list_taint:
            return list_taint[normalized], True
        if normalized in array_taint:
            return array_taint[normalized], True
        builder_match = BUILDER_TOSTRING_RE.search(normalized)
        if builder_match and builder_taint.get(builder_match.group(1), False):
            return True, False
        if normalized in state.tainted_vars:
            return True, False
        referenced = self._assignment_analyzer.referenced_variables(normalized)
        if referenced & state.tainted_vars:
            return True, False
        return False, False

    def _list_taint(self, source_code: str, state: AssignmentState) -> Dict[str, bool]:
        values: Dict[str, bool] = {}
        for list_name, expr in COMMAND_LIST_ADD_RE.findall(source_code):
            tainted, _ = self._command_expr_tainted(
                expr.strip(),
                state=state,
                list_taint={},
                array_taint={},
                builder_taint={},
            )
            values[list_name] = values.get(list_name, False) or tainted
        return values

    def _array_taint(self, source_code: str, state: AssignmentState) -> Dict[str, bool]:
        values: Dict[str, bool] = {}
        for array_name, entries in COMMAND_ARRAY_ASSIGNMENT_RE.findall(source_code):
            tainted, _ = self._command_expr_tainted(
                entries.strip(),
                state=state,
                list_taint={},
                array_taint={},
                builder_taint={},
            )
            values[array_name] = tainted or array_name in state.tainted_vars
        return values

    def _builder_taint(self, source_code: str, state: AssignmentState) -> Dict[str, bool]:
        values: Dict[str, bool] = {}
        for builder_name, expr in COMMAND_APPEND_RE.findall(source_code):
            tainted, _ = self._command_expr_tainted(
                expr.strip(),
                state=state,
                list_taint={},
                array_taint={},
                builder_taint={},
            )
            values[builder_name] = values.get(builder_name, False) or tainted
        return values
