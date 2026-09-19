"""Assignment state tracking and variable taint analysis for policy engine."""

from __future__ import annotations

import re

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
from codegraph.policy.analysis.state_helpers import (
    IF_ASSIGNMENT_RE,
    SIMPLE_ASSIGNMENT_RE,
    VAR_REF_RE,
    AssignmentState,
    _apply_unresolved_if_else_taint_join,
    _apply_unresolved_if_taint_join,
    _clear_var_state,
    _conditional_assignment_spans,
    _mark_tainted,
    _propagate_taint_from_assignments,
    _referenced_variables,
    _set_int_constant,
    _set_string_constant,
    _simulate_assignment_flow,
)

INT_LITERAL_FULL_RE = re.compile(r"^-?\d+$")
CHAR_AT_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\.charAt\((\d+)\)$")
TOP_LEVEL_TERNARY_RE = re.compile(r"^(?P<condition>.+?)\?(?P<when_true>.+?):(?P<when_false>.+)$", re.DOTALL)

__all__ = [
    "CHAR_AT_RE",
    "IF_ASSIGNMENT_RE",
    "IF_ELSE_ASSIGNMENT_RE",
    "INT_LITERAL_FULL_RE",
    "LIST_ADD_VALUE_RE",
    "LIST_GET_VALUE_RE",
    "LIST_REMOVE_INDEX_RE",
    "MAP_GET_ASSIGNMENT_RE",
    "MAP_PUT_VALUE_RE",
    "SIMPLE_ASSIGNMENT_RE",
    "STRING_LITERAL_FULL_RE",
    "SWITCH_BLOCK_RE",
    "TOP_LEVEL_TERNARY_RE",
    "VAR_REF_RE",
    "AssignmentState",
    "AssignmentStateAnalyzer",
    "ConditionalAssignmentResolver",
]


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

        self._apply_unresolved_if_else_taint_join(
            source_code,
            tainted_vars=tainted_vars,
            string_constants=string_constants,
            int_constants=int_constants,
            char_constants=char_constants,
            joined_taint_cutoffs=joined_taint_cutoffs,
            evaluate_constant_boolean_fn=self._evaluate_constant_boolean,
            taint_patterns=self._taint_patterns,
        )
        self._apply_unresolved_if_taint_join(
            source_code,
            tainted_vars=tainted_vars,
            string_constants=string_constants,
            int_constants=int_constants,
            char_constants=char_constants,
            joined_taint_cutoffs=joined_taint_cutoffs,
            evaluate_constant_boolean_fn=self._evaluate_constant_boolean,
            taint_patterns=self._taint_patterns,
        )
        if tainted_vars != tainted_before_join:
            self._propagate_taint_from_assignments(
                source_code,
                tainted_vars,
                joined_taint_cutoffs=joined_taint_cutoffs,
                taint_patterns=self._taint_patterns,
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

    _apply_unresolved_if_else_taint_join = staticmethod(_apply_unresolved_if_else_taint_join)
    _apply_unresolved_if_taint_join = staticmethod(_apply_unresolved_if_taint_join)
    _propagate_taint_from_assignments = staticmethod(_propagate_taint_from_assignments)
    _simulate_assignment_flow = staticmethod(_simulate_assignment_flow)
    _conditional_assignment_spans = staticmethod(_conditional_assignment_spans)
    referenced_variables = staticmethod(_referenced_variables)
    _clear_var_state = staticmethod(_clear_var_state)
    _mark_tainted = staticmethod(_mark_tainted)
    _set_string_constant = staticmethod(_set_string_constant)
    _set_int_constant = staticmethod(_set_int_constant)
    _evaluate_constant_boolean = staticmethod(evaluate_constant_boolean)
    _validate_numeric_value = staticmethod(validate_numeric_value)
    _eval_boolean_ast = staticmethod(eval_boolean_ast)
    _resolve_selected_switch_body = staticmethod(resolve_selected_switch_body)
    _resolve_selected_list_gets = staticmethod(resolve_selected_list_gets)
    _resolve_selected_map_gets = staticmethod(resolve_selected_map_gets)
    _resolve_collection_expr = staticmethod(resolve_collection_expr)
