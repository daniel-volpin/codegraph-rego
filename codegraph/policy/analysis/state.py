"""Assignment state tracking and variable taint analysis for policy engine."""

from __future__ import annotations

import re
from dataclasses import dataclass

from codegraph.policy.analysis.boolean_eval import (
    eval_boolean_ast,
    evaluate_constant_boolean,
    validate_numeric_value,
)
from codegraph.policy.analysis.conditional import (
    IF_ELSE_ASSIGNMENT_RE,
    LIST_ADD_VALUE_RE,
    LIST_GET_VALUE_RE,
    LIST_REMOVE_INDEX_RE,
    MAP_GET_ASSIGNMENT_RE,
    MAP_PUT_VALUE_RE,
    STRING_LITERAL_FULL_RE,
    SWITCH_BLOCK_RE,
    ConditionalAssignmentResolver,
    resolve_collection_expr,
    resolve_selected_list_gets,
    resolve_selected_map_gets,
    resolve_selected_switch_body,
)
from codegraph.policy.analysis.primitives import SourceSanitizer

SIMPLE_ASSIGNMENT_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^;]+);", re.DOTALL)
INT_LITERAL_FULL_RE = re.compile(r"^-?\d+$")
CHAR_AT_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\.charAt\((\d+)\)$")
TOP_LEVEL_TERNARY_RE = re.compile(r"^(?P<condition>.+?)\?(?P<when_true>.+?):(?P<when_false>.+)$", re.DOTALL)
IF_ASSIGNMENT_RE = re.compile(
    r"if\s*\((?P<condition>[^{};]*?)\)\s*(?P<body>\{[^{}]*?[A-Za-z_][A-Za-z0-9_]*\s*=\s*[^;]+;[^{}]*?\}|[A-Za-z_][A-Za-z0-9_]*\s*=\s*[^;]+;)",
    re.DOTALL,
)
VAR_REF_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\b")

__all__ = [
    "IF_ASSIGNMENT_RE",
    "IF_ELSE_ASSIGNMENT_RE",
    "LIST_ADD_VALUE_RE",
    "LIST_GET_VALUE_RE",
    "LIST_REMOVE_INDEX_RE",
    "MAP_GET_ASSIGNMENT_RE",
    "MAP_PUT_VALUE_RE",
    "SIMPLE_ASSIGNMENT_RE",
    "STRING_LITERAL_FULL_RE",
    "SWITCH_BLOCK_RE",
    "AssignmentState",
    "AssignmentStateAnalyzer",
    "ConditionalAssignmentResolver",
]


@dataclass(frozen=True)
class AssignmentState:
    tainted_vars: set[str]
    string_constants: dict[str, str]


class AssignmentStateAnalyzer:
    """Analyzes assignment flow, constant propagation, and taint tracking in source snippets."""

    def __init__(self, taint_patterns=()) -> None:
        self._taint_patterns = taint_patterns
        self._conditional_resolver = ConditionalAssignmentResolver()

    def analyze(self, source_code: str, initial_tainted_vars: set[str] | None = None) -> AssignmentState:
        source_code = SourceSanitizer.strip_comments_and_annotations(source_code)
        tainted_vars = set(initial_tainted_vars or set())
        string_constants: dict[str, str] = {}
        int_constants: dict[str, int] = {}
        char_constants: dict[str, str] = {}
        conditional_spans = self._conditional_assignment_spans(source_code)

        for match in SIMPLE_ASSIGNMENT_RE.finditer(source_code):
            if any(start <= match.start() and match.end() <= end for start, end in conditional_spans):
                continue
            var = match.group(1)
            rhs = match.group(2).strip()

            ternary_match = TOP_LEVEL_TERNARY_RE.match(rhs)
            if ternary_match:
                decision = self._evaluate_constant_boolean(ternary_match.group("condition"), int_constants)
                if decision is not None:
                    rhs = ternary_match.group("when_true" if decision else "when_false").strip()

            if any(pattern.search(rhs) for pattern in self._taint_patterns):
                self._mark_tainted(
                    var,
                    tainted_vars=tainted_vars,
                    string_constants=string_constants,
                    int_constants=int_constants,
                    char_constants=char_constants,
                )
                continue

            literal_match = STRING_LITERAL_FULL_RE.match(rhs)
            if literal_match:
                self._set_string_constant(
                    var,
                    literal_match.group(1),
                    tainted_vars=tainted_vars,
                    string_constants=string_constants,
                    int_constants=int_constants,
                    char_constants=char_constants,
                )
                continue

            if INT_LITERAL_FULL_RE.match(rhs):
                self._set_int_constant(
                    var,
                    int(rhs),
                    tainted_vars=tainted_vars,
                    string_constants=string_constants,
                    int_constants=int_constants,
                    char_constants=char_constants,
                )
                continue

            char_match = CHAR_AT_RE.match(rhs)
            if char_match:
                source_var = char_match.group(1)
                index = int(char_match.group(2))
                text = string_constants.get(source_var)
                if text is not None and 0 <= index < len(text):
                    char_constants[var] = text[index]
                    tainted_vars.discard(var)
                    string_constants.pop(var, None)
                    int_constants.pop(var, None)
                    continue

            referenced = self.referenced_variables(rhs)
            if referenced & tainted_vars:
                self._mark_tainted(
                    var,
                    tainted_vars=tainted_vars,
                    string_constants=string_constants,
                    int_constants=int_constants,
                    char_constants=char_constants,
                )
                continue

            self._clear_var_state(
                var,
                tainted_vars=tainted_vars,
                string_constants=string_constants,
                int_constants=int_constants,
                char_constants=char_constants,
            )

        collapsed_if_else = self._conditional_resolver.resolve(source_code, int_constants)
        if collapsed_if_else != source_code:
            return self.analyze(collapsed_if_else, initial_tainted_vars=initial_tainted_vars)

        tainted_before_join = set(tainted_vars)
        joined_taint_cutoffs: dict[str, int] = {}

        # For unresolved branches, keep taint if either side may assign tainted input.
        self._apply_unresolved_if_else_taint_join(
            source_code,
            tainted_vars=tainted_vars,
            string_constants=string_constants,
            int_constants=int_constants,
            char_constants=char_constants,
            joined_taint_cutoffs=joined_taint_cutoffs,
        )
        self._apply_unresolved_if_taint_join(
            source_code,
            tainted_vars=tainted_vars,
            string_constants=string_constants,
            int_constants=int_constants,
            char_constants=char_constants,
            joined_taint_cutoffs=joined_taint_cutoffs,
        )
        if tainted_vars != tainted_before_join:
            self._propagate_taint_from_assignments(
                source_code,
                tainted_vars,
                joined_taint_cutoffs=joined_taint_cutoffs,
            )

        collapsed_maps = resolve_selected_map_gets(source_code, string_constants, tainted_vars)
        if collapsed_maps != source_code:
            return self.analyze(collapsed_maps, initial_tainted_vars=initial_tainted_vars)

        collapsed_lists = resolve_selected_list_gets(source_code, string_constants, tainted_vars)
        if collapsed_lists != source_code:
            return self.analyze(collapsed_lists, initial_tainted_vars=initial_tainted_vars)

        collapsed = resolve_selected_switch_body(source_code, char_constants)
        if collapsed != source_code:
            return self.analyze(collapsed, initial_tainted_vars=initial_tainted_vars)

        return AssignmentState(tainted_vars=tainted_vars, string_constants=string_constants)

    def _apply_unresolved_if_else_taint_join(
        self,
        source_code: str,
        *,
        tainted_vars: set[str],
        string_constants: dict[str, str],
        int_constants: dict[str, int],
        char_constants: dict[str, str],
        joined_taint_cutoffs: dict[str, int],
    ) -> None:
        for match in IF_ELSE_ASSIGNMENT_RE.finditer(source_code):
            decision = self._evaluate_constant_boolean(match.group("condition"), int_constants)
            if decision is not None:
                continue
            true_taints = self._simulate_assignment_flow(match.group("when_true"), tainted_vars)
            false_taints = self._simulate_assignment_flow(match.group("when_false"), tainted_vars)
            joined_tainted_vars = {
                var
                for var in (set(true_taints) & set(false_taints))
                if true_taints.get(var, False) or false_taints.get(var, False)
            }
            for var in joined_tainted_vars:
                joined_taint_cutoffs[var] = max(joined_taint_cutoffs.get(var, 0), match.end())
                self._mark_tainted(
                    var,
                    tainted_vars=tainted_vars,
                    string_constants=string_constants,
                    int_constants=int_constants,
                    char_constants=char_constants,
                )

    def _expr_is_tainted(self, expr: str, tainted_vars: set[str]) -> bool:
        if any(pattern.search(expr) for pattern in self._taint_patterns):
            return True
        return bool(self.referenced_variables(expr) & tainted_vars)

    def _apply_unresolved_if_taint_join(
        self,
        source_code: str,
        *,
        tainted_vars: set[str],
        string_constants: dict[str, str],
        int_constants: dict[str, int],
        char_constants: dict[str, str],
        joined_taint_cutoffs: dict[str, int],
    ) -> None:
        for match in IF_ASSIGNMENT_RE.finditer(source_code):
            if IF_ELSE_ASSIGNMENT_RE.fullmatch(match.group(0).strip()):
                continue
            decision = self._evaluate_constant_boolean(match.group("condition"), int_constants)
            if decision is not None:
                continue
            branch_taints = self._simulate_assignment_flow(match.group("body"), tainted_vars)
            for var, is_tainted in branch_taints.items():
                if not is_tainted:
                    continue
                joined_taint_cutoffs[var] = max(joined_taint_cutoffs.get(var, 0), match.end())
                self._mark_tainted(
                    var,
                    tainted_vars=tainted_vars,
                    string_constants=string_constants,
                    int_constants=int_constants,
                    char_constants=char_constants,
                )

    def _propagate_taint_from_assignments(
        self,
        source_code: str,
        tainted_vars: set[str],
        *,
        joined_taint_cutoffs: dict[str, int],
    ) -> None:
        unresolved_spans = self._conditional_assignment_spans(source_code)
        while True:
            updated_taints = set(tainted_vars)
            for match in SIMPLE_ASSIGNMENT_RE.finditer(source_code):
                if any(start <= match.start() and match.end() <= end for start, end in unresolved_spans):
                    continue
                var = match.group(1)
                rhs = match.group(2).strip()
                rhs_is_tainted = self._expr_is_tainted(rhs, updated_taints)
                if rhs_is_tainted:
                    updated_taints.add(var)
                else:
                    if match.start() < joined_taint_cutoffs.get(var, -1):
                        continue
                    updated_taints.discard(var)
            if updated_taints == tainted_vars:
                return
            tainted_vars.clear()
            tainted_vars.update(updated_taints)

    def _simulate_assignment_flow(self, source_code: str, tainted_vars: set[str]) -> dict[str, bool]:
        simulated_taints = set(tainted_vars)
        assigned_vars: list[str] = []
        for assign in SIMPLE_ASSIGNMENT_RE.finditer(source_code):
            var = assign.group(1)
            rhs = assign.group(2).strip()
            rhs_is_tainted = self._expr_is_tainted(rhs, simulated_taints)
            if rhs_is_tainted:
                simulated_taints.add(var)
            else:
                simulated_taints.discard(var)
            if var not in assigned_vars:
                assigned_vars.append(var)
        return {var: var in simulated_taints for var in assigned_vars}

    @staticmethod
    def _conditional_assignment_spans(source_code: str) -> list[tuple[int, int]]:
        spans = [match.span() for match in IF_ELSE_ASSIGNMENT_RE.finditer(source_code)]
        for match in IF_ASSIGNMENT_RE.finditer(source_code):
            if any(start <= match.start() and match.end() <= end for start, end in spans):
                continue
            spans.append(match.span())
        return spans

    @staticmethod
    def referenced_variables(expr: str) -> set[str]:
        return set(VAR_REF_RE.findall(expr))

    @staticmethod
    def _clear_var_state(
        var: str,
        *,
        tainted_vars: set[str],
        string_constants: dict[str, str],
        int_constants: dict[str, int],
        char_constants: dict[str, str],
    ) -> None:
        tainted_vars.discard(var)
        string_constants.pop(var, None)
        int_constants.pop(var, None)
        char_constants.pop(var, None)

    @classmethod
    def _mark_tainted(
        cls,
        var: str,
        *,
        tainted_vars: set[str],
        string_constants: dict[str, str],
        int_constants: dict[str, int],
        char_constants: dict[str, str],
    ) -> None:
        cls._clear_var_state(
            var,
            tainted_vars=tainted_vars,
            string_constants=string_constants,
            int_constants=int_constants,
            char_constants=char_constants,
        )
        tainted_vars.add(var)

    @classmethod
    def _set_string_constant(
        cls,
        var: str,
        value: str,
        *,
        tainted_vars: set[str],
        string_constants: dict[str, str],
        int_constants: dict[str, int],
        char_constants: dict[str, str],
    ) -> None:
        cls._clear_var_state(
            var,
            tainted_vars=tainted_vars,
            string_constants=string_constants,
            int_constants=int_constants,
            char_constants=char_constants,
        )
        string_constants[var] = value

    @classmethod
    def _set_int_constant(
        cls,
        var: str,
        value: int,
        *,
        tainted_vars: set[str],
        string_constants: dict[str, str],
        int_constants: dict[str, int],
        char_constants: dict[str, str],
    ) -> None:
        cls._clear_var_state(
            var,
            tainted_vars=tainted_vars,
            string_constants=string_constants,
            int_constants=int_constants,
            char_constants=char_constants,
        )
        int_constants[var] = value

    @staticmethod
    def _evaluate_constant_boolean(expr: str, int_constants: dict[str, int]) -> bool | None:
        return evaluate_constant_boolean(expr, int_constants)

    @staticmethod
    def _validate_numeric_value(value: int | float | bool) -> int | float | bool:
        return validate_numeric_value(value)

    @staticmethod
    def _eval_boolean_ast(node) -> int | float | bool:
        return eval_boolean_ast(node)

    @staticmethod
    def _resolve_selected_switch_body(source_code: str, char_constants: dict[str, str]) -> str:
        return resolve_selected_switch_body(source_code, char_constants)

    @classmethod
    def _resolve_selected_list_gets(
        cls,
        source_code: str,
        string_constants: dict[str, str],
        tainted_vars: set[str],
    ) -> str:
        return resolve_selected_list_gets(source_code, string_constants, tainted_vars)

    @classmethod
    def _resolve_selected_map_gets(
        cls,
        source_code: str,
        string_constants: dict[str, str],
        tainted_vars: set[str],
    ) -> str:
        return resolve_selected_map_gets(source_code, string_constants, tainted_vars)

    @staticmethod
    def _resolve_collection_expr(
        expr: str,
        string_constants: dict[str, str],
        tainted_vars: set[str],
    ) -> str | None:
        return resolve_collection_expr(expr, string_constants, tainted_vars)

