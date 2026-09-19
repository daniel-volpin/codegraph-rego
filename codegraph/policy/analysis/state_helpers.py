from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from codegraph.policy.analysis.conditional import IF_ELSE_ASSIGNMENT_RE

IF_ASSIGNMENT_RE = re.compile(
    r"if\s*\((?P<condition>[^{};]*?)\)\s*(?P<body>\{[^{}]*?[A-Za-z_][A-Za-z0-9_]*\s*=\s*[^;]+;[^{}]*?\}|[A-Za-z_][A-Za-z0-9_]*\s*=\s*[^;]+;)",
    re.DOTALL,
)
SIMPLE_ASSIGNMENT_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^;]+);", re.DOTALL)
VAR_REF_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\b")


@dataclass(frozen=True)
class AssignmentState:
    tainted_vars: set[str]
    string_constants: dict[str, str]


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


def _mark_tainted(
    var: str,
    *,
    tainted_vars: set[str],
    string_constants: dict[str, str],
    int_constants: dict[str, int],
    char_constants: dict[str, str],
) -> None:
    _clear_var_state(
        var,
        tainted_vars=tainted_vars,
        string_constants=string_constants,
        int_constants=int_constants,
        char_constants=char_constants,
    )
    tainted_vars.add(var)


def _set_string_constant(
    var: str,
    value: str,
    *,
    tainted_vars: set[str],
    string_constants: dict[str, str],
    int_constants: dict[str, int],
    char_constants: dict[str, str],
) -> None:
    _clear_var_state(
        var,
        tainted_vars=tainted_vars,
        string_constants=string_constants,
        int_constants=int_constants,
        char_constants=char_constants,
    )
    string_constants[var] = value


def _set_int_constant(
    var: str,
    value: int,
    *,
    tainted_vars: set[str],
    string_constants: dict[str, str],
    int_constants: dict[str, int],
    char_constants: dict[str, str],
) -> None:
    _clear_var_state(
        var,
        tainted_vars=tainted_vars,
        string_constants=string_constants,
        int_constants=int_constants,
        char_constants=char_constants,
    )
    int_constants[var] = value


def _conditional_assignment_spans(source_code: str) -> list[tuple[int, int]]:
    spans = [match.span() for match in IF_ELSE_ASSIGNMENT_RE.finditer(source_code)]
    for match in IF_ASSIGNMENT_RE.finditer(source_code):
        if any(start <= match.start() and match.end() <= end for start, end in spans):
            continue
        spans.append(match.span())
    return spans


def _referenced_variables(expr: str) -> set[str]:
    return set(VAR_REF_RE.findall(expr))


def _expr_is_tainted(expr: str, tainted_vars: set[str], taint_patterns: Sequence[Any]) -> bool:
    if any(pattern.search(expr) for pattern in taint_patterns):
        return True
    return bool(_referenced_variables(expr) & tainted_vars)


def _simulate_assignment_flow(source_code: str, tainted_vars: set[str], taint_patterns: Sequence[Any]) -> dict[str, bool]:
    simulated_taints = set(tainted_vars)
    assigned_vars: list[str] = []
    for assign in SIMPLE_ASSIGNMENT_RE.finditer(source_code):
        var = assign.group(1)
        rhs = assign.group(2).strip()
        rhs_is_tainted = _expr_is_tainted(rhs, simulated_taints, taint_patterns)
        if rhs_is_tainted:
            simulated_taints.add(var)
        else:
            simulated_taints.discard(var)
        if var not in assigned_vars:
            assigned_vars.append(var)
    return {var: var in simulated_taints for var in assigned_vars}


def _apply_unresolved_if_else_taint_join(
    source_code: str,
    *,
    tainted_vars: set[str],
    string_constants: dict[str, str],
    int_constants: dict[str, int],
    char_constants: dict[str, str],
    joined_taint_cutoffs: dict[str, int],
    evaluate_constant_boolean_fn: Any,
    taint_patterns: Sequence[Any],
) -> None:
    for match in IF_ELSE_ASSIGNMENT_RE.finditer(source_code):
        decision = evaluate_constant_boolean_fn(match.group("condition"), int_constants)
        if decision is not None:
            continue
        true_taints = _simulate_assignment_flow(match.group("when_true"), tainted_vars, taint_patterns)
        false_taints = _simulate_assignment_flow(match.group("when_false"), tainted_vars, taint_patterns)
        joined_tainted_vars = {
            var
            for var in (set(true_taints) & set(false_taints))
            if true_taints.get(var, False) or false_taints.get(var, False)
        }
        for var in joined_tainted_vars:
            joined_taint_cutoffs[var] = max(joined_taint_cutoffs.get(var, 0), match.end())
            _mark_tainted(
                var,
                tainted_vars=tainted_vars,
                string_constants=string_constants,
                int_constants=int_constants,
                char_constants=char_constants,
            )


def _apply_unresolved_if_taint_join(
    source_code: str,
    *,
    tainted_vars: set[str],
    string_constants: dict[str, str],
    int_constants: dict[str, int],
    char_constants: dict[str, str],
    joined_taint_cutoffs: dict[str, int],
    evaluate_constant_boolean_fn: Any,
    taint_patterns: Sequence[Any],
) -> None:
    for match in IF_ASSIGNMENT_RE.finditer(source_code):
        if IF_ELSE_ASSIGNMENT_RE.fullmatch(match.group(0).strip()):
            continue
        decision = evaluate_constant_boolean_fn(match.group("condition"), int_constants)
        if decision is not None:
            continue
        branch_taints = _simulate_assignment_flow(match.group("body"), tainted_vars, taint_patterns)
        for var, is_tainted in branch_taints.items():
            if not is_tainted:
                continue
            joined_taint_cutoffs[var] = max(joined_taint_cutoffs.get(var, 0), match.end())
            _mark_tainted(
                var,
                tainted_vars=tainted_vars,
                string_constants=string_constants,
                int_constants=int_constants,
                char_constants=char_constants,
            )


def _propagate_taint_from_assignments(
    source_code: str,
    tainted_vars: set[str],
    *,
    joined_taint_cutoffs: dict[str, int],
    taint_patterns: Sequence[Any],
) -> None:
    unresolved_spans = _conditional_assignment_spans(source_code)
    while True:
        updated_taints = set(tainted_vars)
        for match in SIMPLE_ASSIGNMENT_RE.finditer(source_code):
            if any(start <= match.start() and match.end() <= end for start, end in unresolved_spans):
                continue
            var = match.group(1)
            rhs = match.group(2).strip()
            rhs_is_tainted = _expr_is_tainted(rhs, updated_taints, taint_patterns)
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
