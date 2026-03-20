from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict

from codegraph.policy.analysis.primitives import SourceSanitizer

SIMPLE_ASSIGNMENT_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^;]+);", re.DOTALL)
LIST_ADD_VALUE_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)\.add\(\s*([^;]+?)\s*\)\s*;', re.DOTALL)
LIST_REMOVE_INDEX_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)\.remove\(\s*(\d+)\s*\)\s*;', re.DOTALL)
LIST_GET_VALUE_RE = re.compile(
    r'([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:\([^)]+\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\.get\(\s*(\d+)\s*\)\s*;',
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
STRING_LITERAL_FULL_RE = re.compile(r'^"([^"\\]*(?:\\.[^"\\]*)*)"$', re.DOTALL)
INT_LITERAL_FULL_RE = re.compile(r"^-?\d+$")
CHAR_AT_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\.charAt\((\d+)\)$")
TOP_LEVEL_TERNARY_RE = re.compile(r"^(?P<condition>.+?)\?(?P<when_true>.+?):(?P<when_false>.+)$", re.DOTALL)
SWITCH_BLOCK_RE = re.compile(r"switch\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*\{(.*?)\}", re.DOTALL)
IF_ELSE_ASSIGNMENT_RE = re.compile(
    r"if\s*\((?P<condition>[^{};]*?)\)\s*(?P<when_true>\{?\s*[A-Za-z_][A-Za-z0-9_]*\s*=\s*[^;]+;\s*\}?)\s*else\s*(?P<when_false>\{?\s*[A-Za-z_][A-Za-z0-9_]*\s*=\s*[^;]+;\s*\}?)",
    re.DOTALL,
)
VAR_REF_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\b")


@dataclass(frozen=True)
class AssignmentState:
    tainted_vars: set[str]
    string_constants: Dict[str, str]


class AssignmentStateAnalyzer:
    def __init__(self, taint_patterns=()) -> None:
        self._taint_patterns = taint_patterns
        self._conditional_resolver = ConditionalAssignmentResolver()

    def analyze(self, source_code: str, initial_tainted_vars: set[str] | None = None) -> AssignmentState:
        source_code = SourceSanitizer.strip_comments_and_annotations(source_code)
        tainted_vars = set(initial_tainted_vars or set())
        string_constants: Dict[str, str] = {}
        int_constants: Dict[str, int] = {}
        char_constants: Dict[str, str] = {}

        for match in SIMPLE_ASSIGNMENT_RE.finditer(source_code):
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

        collapsed_maps = self._resolve_selected_map_gets(source_code, string_constants, tainted_vars)
        if collapsed_maps != source_code:
            return self.analyze(collapsed_maps, initial_tainted_vars=initial_tainted_vars)

        collapsed_lists = self._resolve_selected_list_gets(source_code, string_constants, tainted_vars)
        if collapsed_lists != source_code:
            return self.analyze(collapsed_lists, initial_tainted_vars=initial_tainted_vars)

        collapsed = self._resolve_selected_switch_body(source_code, char_constants)
        if collapsed != source_code:
            return self.analyze(collapsed, initial_tainted_vars=initial_tainted_vars)

        return AssignmentState(tainted_vars=tainted_vars, string_constants=string_constants)

    @staticmethod
    def referenced_variables(expr: str) -> set[str]:
        return set(VAR_REF_RE.findall(expr))

    @staticmethod
    def _clear_var_state(
        var: str,
        *,
        tainted_vars: set[str],
        string_constants: Dict[str, str],
        int_constants: Dict[str, int],
        char_constants: Dict[str, str],
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
        string_constants: Dict[str, str],
        int_constants: Dict[str, int],
        char_constants: Dict[str, str],
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
        string_constants: Dict[str, str],
        int_constants: Dict[str, int],
        char_constants: Dict[str, str],
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
        string_constants: Dict[str, str],
        int_constants: Dict[str, int],
        char_constants: Dict[str, str],
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
    def _evaluate_constant_boolean(expr: str, int_constants: Dict[str, int]) -> bool | None:
        normalized = expr
        for var, value in int_constants.items():
            normalized = re.sub(rf"\b{re.escape(var)}\b", str(value), normalized)
        normalized = normalized.replace("&&", " and ").replace("||", " or ")
        if re.search(r"[A-Za-z_]", normalized):
            return None
        if not re.fullmatch(r"[0-9\s()+\-*/%<>=!&|.andor]+", normalized):
            return None
        try:
            value = eval(normalized, {"__builtins__": {}}, {})
        except Exception:
            return None
        return bool(value) if isinstance(value, (bool, int, float)) else None

    @staticmethod
    def _resolve_selected_switch_body(source_code: str, char_constants: Dict[str, str]) -> str:
        def _replace(match: re.Match[str]) -> str:
            target = match.group(1)
            body = match.group(2)
            constant = char_constants.get(target)
            if constant is None:
                return ""
            case_match = re.search(rf"case\s+'{re.escape(constant)}'\s*:", body, re.DOTALL)
            if case_match:
                tail = body[case_match.end():]
                tail = re.sub(r"^(?:\s*case\s+'[^']+'\s*:\s*)+", "", tail, flags=re.DOTALL)
                stmt_match = re.search(r"(.*?)(?=break;|default:|\Z)", tail, re.DOTALL)
                if stmt_match:
                    return stmt_match.group(1)
            default_match = re.search(r"default\s*:(.*?)(?=break;|\Z)", body, re.DOTALL)
            return default_match.group(1) if default_match else ""

        return SWITCH_BLOCK_RE.sub(_replace, source_code)

    @classmethod
    def _resolve_selected_list_gets(
        cls,
        source_code: str,
        string_constants: Dict[str, str],
        tainted_vars: set[str],
    ) -> str:
        items: Dict[str, list[str]] = {}
        for list_name, raw_value in LIST_ADD_VALUE_RE.findall(source_code):
            resolved = cls._resolve_collection_expr(raw_value.strip(), string_constants, tainted_vars)
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

    @classmethod
    def _resolve_selected_map_gets(
        cls,
        source_code: str,
        string_constants: Dict[str, str],
        tainted_vars: set[str],
    ) -> str:
        entries: Dict[str, Dict[str, str]] = {}
        for map_name, key, raw_value in MAP_PUT_VALUE_RE.findall(source_code):
            resolved = cls._resolve_collection_expr(raw_value.strip(), string_constants, tainted_vars)
            if resolved is not None:
                entries.setdefault(map_name, {})[key] = resolved

        def _replace(match: re.Match[str]) -> str:
            target_var, map_name, key = match.groups()
            resolved = entries.get(map_name, {}).get(key)
            if resolved is None:
                return match.group(0)
            return f"{target_var} = {resolved};"

        return MAP_GET_ASSIGNMENT_RE.sub(_replace, source_code)

    @staticmethod
    def _resolve_collection_expr(
        expr: str,
        string_constants: Dict[str, str],
        tainted_vars: set[str],
    ) -> str | None:
        literal_match = STRING_LITERAL_FULL_RE.match(expr)
        if literal_match:
            return expr
        if expr in string_constants:
            return f'"{string_constants[expr]}"'
        if expr in tainted_vars:
            return expr
        return None


class ConditionalAssignmentResolver:
    @staticmethod
    def resolve(source_code: str, int_constants: Dict[str, int]) -> str:
        def _replace(match: re.Match[str]) -> str:
            decision = AssignmentStateAnalyzer._evaluate_constant_boolean(match.group("condition"), int_constants)
            if decision is None:
                return match.group(0)
            chosen_branch = match.group("when_true" if decision else "when_false").strip()
            normalized = chosen_branch
            if normalized.startswith("{") and normalized.endswith("}"):
                normalized = normalized[1:-1].strip()
            return normalized

        return IF_ELSE_ASSIGNMENT_RE.sub(_replace, source_code)
