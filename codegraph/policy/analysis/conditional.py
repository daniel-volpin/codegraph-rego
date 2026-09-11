"""Conditional branching and collection assignment resolution for static analysis."""

from __future__ import annotations

import re

from codegraph.policy.analysis.boolean_eval import evaluate_constant_boolean

STRING_LITERAL_FULL_RE = re.compile(r'^"([^"\\]*(?:\\.[^"\\]*)*)"$', re.DOTALL)
LIST_ADD_VALUE_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\.add\(\s*([^;]+?)\s*\)\s*;", re.DOTALL)
LIST_REMOVE_INDEX_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\.remove\(\s*(\d+)\s*\)\s*;", re.DOTALL)
LIST_GET_VALUE_RE = re.compile(
    r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:\([^)]+\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\.get\(\s*(\d+)\s*\)\s*;",
    re.DOTALL,
)
MAP_PUT_VALUE_RE = re.compile(
    r'([A-Za-z_][A-Za-z0-9_]*)\.put\(\s*"([^"]+)"\s*,\s*([^;]+?)\s*\)\s*;',
    re.DOTALL,
)
MAP_GET_ASSIGNMENT_RE = re.compile(
    r'([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:\([^)]+\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\.get\(\s*"([^"]+)"\s*\)\s*;',
    re.DOTALL,
)
SWITCH_BLOCK_RE = re.compile(r"switch\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*\{(.*?)\}", re.DOTALL)
IF_ELSE_ASSIGNMENT_RE = re.compile(
    r"if\s*\((?P<condition>[^{};]*?)\)\s*(?P<when_true>\{[^{}]*\}|[A-Za-z_][A-Za-z0-9_]*\s*=\s*[^;]+;)\s*else\s*(?P<when_false>\{[^{}]*\}|[A-Za-z_][A-Za-z0-9_]*\s*=\s*[^;]+;)",
    re.DOTALL,
)


def resolve_collection_expr(
    expr: str,
    string_constants: dict[str, str],
    tainted_vars: set[str],
) -> str | None:
    """Resolve an expression stored into or retrieved from a collection."""
    literal_match = STRING_LITERAL_FULL_RE.match(expr)
    if literal_match:
        return expr
    if expr in string_constants:
        return f'"{string_constants[expr]}"'
    if expr in tainted_vars:
        return expr
    return None


def resolve_selected_list_gets(
    source_code: str,
    string_constants: dict[str, str],
    tainted_vars: set[str],
) -> str:
    """Resolve deterministic List.add / List.remove / List.get sequences."""
    items: dict[str, list[str]] = {}
    for list_name, raw_value in LIST_ADD_VALUE_RE.findall(source_code):
        resolved = resolve_collection_expr(raw_value.strip(), string_constants, tainted_vars)
        if resolved is not None:
            items.setdefault(list_name, []).append(resolved)
    for list_name, raw_index in LIST_REMOVE_INDEX_RE.findall(source_code):
        values = items.get(list_name)
        if values is None:
            continue
        index = int(raw_index)
        if 0 <= index < len(values):
            values.pop(index)

    def _replace(match: re.Match[str]) -> str:
        target_var, list_name, raw_index = match.groups()
        values = items.get(list_name)
        if values is None:
            return match.group(0)
        index = int(raw_index)
        if not (0 <= index < len(values)):
            return match.group(0)
        return f"{target_var} = {values[index]};"

    return LIST_GET_VALUE_RE.sub(_replace, source_code)


def resolve_selected_map_gets(
    source_code: str,
    string_constants: dict[str, str],
    tainted_vars: set[str],
) -> str:
    """Resolve deterministic Map.put / Map.get sequences with string keys."""
    entries: dict[str, dict[str, str]] = {}
    for map_name, key, raw_value in MAP_PUT_VALUE_RE.findall(source_code):
        resolved = resolve_collection_expr(raw_value.strip(), string_constants, tainted_vars)
        if resolved is not None:
            entries.setdefault(map_name, {})[key] = resolved

    def _replace(match: re.Match[str]) -> str:
        target_var, map_name, key = match.groups()
        resolved = entries.get(map_name, {}).get(key)
        if resolved is None:
            return match.group(0)
        return f"{target_var} = {resolved};"

    return MAP_GET_ASSIGNMENT_RE.sub(_replace, source_code)


def resolve_selected_switch_body(source_code: str, char_constants: dict[str, str]) -> str:
    """Collapse switch statements on known character constants to their matching branch."""
    def _replace(match: re.Match[str]) -> str:
        target = match.group(1)
        body = match.group(2)
        constant = char_constants.get(target)
        if constant is None:
            return ""
        case_match = re.search(rf"case\s+'{re.escape(constant)}'\s*:", body, re.DOTALL)
        if case_match:
            tail = body[case_match.end() :]
            tail = re.sub(r"^(?:\s*case\s+'[^']+'\s*:\s*)+", "", tail, flags=re.DOTALL)
            stmt_match = re.search(r"(.*?)(?=break;|default:|\Z)", tail, re.DOTALL)
            if stmt_match:
                return stmt_match.group(1)
        default_match = re.search(r"default\s*:(.*?)(?=break;|\Z)", body, re.DOTALL)
        return default_match.group(1) if default_match else ""

    return SWITCH_BLOCK_RE.sub(_replace, source_code)


class ConditionalAssignmentResolver:
    """Collapses if-else blocks whose conditions evaluate to known booleans."""

    @staticmethod
    def resolve(source_code: str, int_constants: dict[str, int]) -> str:
        def _replace(match: re.Match[str]) -> str:
            decision = evaluate_constant_boolean(match.group("condition"), int_constants)
            if decision is None:
                return match.group(0)
            chosen_branch = match.group("when_true" if decision else "when_false").strip()
            normalized = chosen_branch
            if normalized.startswith("{") and normalized.endswith("}"):
                normalized = normalized[1:-1].strip()
            return normalized

        return IF_ELSE_ASSIGNMENT_RE.sub(_replace, source_code)
