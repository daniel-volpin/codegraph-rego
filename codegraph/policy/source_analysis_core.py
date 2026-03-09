from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict

MD5_LITERAL_RE = re.compile(
    r'MessageDigest\s*\.\s*getInstance\s*\(\s*"([^"]+)"\s*(?:,|\))',
    re.IGNORECASE,
)
MD5_VAR_RE = re.compile(
    r"MessageDigest\s*\.\s*getInstance\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)",
    re.IGNORECASE,
)
STRING_ASSIGN_RE = re.compile(
    r'(?:final\s+)?String\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"([^"]+)"',
    re.IGNORECASE,
)
CIPHER_LITERAL_RE = re.compile(
    r'Cipher\s*\.\s*getInstance\s*\(\s*"([^"]+)"\s*(?:,|\))',
    re.IGNORECASE,
)
INSECURE_RANDOM_PATTERNS = (
    re.compile(r"new\s+(?:java\.util\.)?Random\s*\(", re.IGNORECASE),
    re.compile(r"(?:java\.lang\.)?Math\s*\.\s*random\s*\(", re.IGNORECASE),
    re.compile(r"(?:java\.util\.concurrent\.)?ThreadLocalRandom\s*\.\s*current\s*\(", re.IGNORECASE),
)
SHA1_PRNG_RE = re.compile(
    r'(?:java\.security\.)?SecureRandom\s*\.\s*getInstance\s*\(\s*"SHA1PRNG"\s*\)',
    re.IGNORECASE,
)
UNTRUSTED_INPUT_PATTERNS = (
    re.compile(r"getParameter\s*\(", re.IGNORECASE),
    re.compile(r"getHeader\s*\(", re.IGNORECASE),
    re.compile(r"getQueryString\s*\(", re.IGNORECASE),
    re.compile(r"getCookies\s*\(", re.IGNORECASE),
)
EXTENDED_UNTRUSTED_INPUT_PATTERNS = (
    *UNTRUSTED_INPUT_PATTERNS,
    re.compile(r"getParameterMap\s*\(", re.IGNORECASE),
    re.compile(r"getParameterValues\s*\(", re.IGNORECASE),
    re.compile(r"getParameterNames\s*\(", re.IGNORECASE),
    re.compile(r"getHeaders\s*\(", re.IGNORECASE),
    re.compile(r"getTheParameter\s*\(", re.IGNORECASE),
)
SQL_UNTRUSTED_INPUT_PATTERNS = EXTENDED_UNTRUSTED_INPUT_PATTERNS
PATH_LDAP_UNTRUSTED_INPUT_PATTERNS = EXTENDED_UNTRUSTED_INPUT_PATTERNS
COMMAND_UNTRUSTED_INPUT_PATTERNS = EXTENDED_UNTRUSTED_INPUT_PATTERNS
PATH_TRAVERSAL_PATTERNS = (
    re.compile(r"new\s+java\.io\.File\s*\(", re.IGNORECASE),
    re.compile(r"new\s+java\.io\.FileInputStream\s*\(", re.IGNORECASE),
    re.compile(r"new\s+java\.io\.FileOutputStream\s*\(", re.IGNORECASE),
    re.compile(r"Files\s*\.\s*newInputStream\s*\(", re.IGNORECASE),
    re.compile(r"Paths\s*\.\s*get\s*\(", re.IGNORECASE),
    re.compile(r"new\s+java\.io\.FileReader\s*\(", re.IGNORECASE),
)
PATH_DYNAMIC_CONSTRUCTION_PATTERNS = (
    re.compile(r"\b(?:file|path|uri)\w*\s*=\s*[^;\n]*\+", re.IGNORECASE),
    re.compile(
        r"new\s+java\.io\.(?:File|FileInputStream|FileOutputStream|FileReader)\s*\([^;\n]*\+",
        re.IGNORECASE,
    ),
    re.compile(r"new\s+java\.net\.URI\s*\([^;\n]*\+", re.IGNORECASE),
)
PATH_DYNAMIC_ARGUMENT_PATTERNS = (
    re.compile(r"new\s+java\.io\.File\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*(?:,|\))", re.IGNORECASE),
    re.compile(r"new\s+java\.io\.FileInputStream\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*(?:,|\))", re.IGNORECASE),
    re.compile(r"new\s+java\.io\.FileOutputStream\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*(?:,|\))", re.IGNORECASE),
    re.compile(r"new\s+java\.io\.FileReader\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*(?:,|\))", re.IGNORECASE),
    re.compile(r"Paths\s*\.\s*get\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*(?:,|\))", re.IGNORECASE),
)
PATH_SINK_VARIABLE_PATTERNS = (
    re.compile(r"new\s+java\.io\.File\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:,|\))", re.IGNORECASE),
    re.compile(r"new\s+java\.io\.FileInputStream\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:,|\))", re.IGNORECASE),
    re.compile(r"new\s+java\.io\.FileOutputStream\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:,|\))", re.IGNORECASE),
    re.compile(r"new\s+java\.io\.FileReader\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:,|\))", re.IGNORECASE),
    re.compile(r"Paths\s*\.\s*get\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:,|\))", re.IGNORECASE),
)
DIRECT_PATH_UNTRUSTED_PATTERNS = (
    re.compile(
        r"new\s+java\.io\.(?:File|FileInputStream|FileOutputStream|FileReader)\s*\([^;\n]*(?:getParameter|getHeader|getQueryString|getCookies)\s*\(",
        re.IGNORECASE,
    ),
    re.compile(r"Paths\s*\.\s*get\s*\([^;\n]*(?:getParameter|getHeader|getQueryString|getCookies)\s*\(", re.IGNORECASE),
    re.compile(r"\b(?:file|path|uri)\w*\s*=\s*[^;\n]*(?:getParameter|getHeader|getQueryString|getCookies)\s*\(", re.IGNORECASE),
)
CMDI_PATTERNS = (
    re.compile(r"\.exec\s*\(", re.IGNORECASE),
    re.compile(r"new\s+ProcessBuilder\s*\(", re.IGNORECASE),
    re.compile(r"\.command\s*\(", re.IGNORECASE),
)
COMMAND_VARIABLE_EXEC_PATTERN = re.compile(r"\.exec\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*(?:,|\))", re.IGNORECASE)
COMMAND_LIST_ADD_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)\.add\(\s*([^;]+?)\s*\)\s*;', re.DOTALL)
COMMAND_ARRAY_ASSIGNMENT_RE = re.compile(
    r'(?:[A-Za-z_][A-Za-z0-9_$.<>\[\]]+\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:new\s+[A-Za-z_][A-Za-z0-9_$.<>\[\]]*\[\]\s*)?\{(.*?)\}\s*;',
    re.DOTALL,
)
COMMAND_APPEND_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)\.append\(\s*([^;]+?)\s*\)\s*;', re.DOTALL)
COMMAND_EXEC_MULTI_ARG_RE = re.compile(
    r'\.exec\s*\(\s*(?P<first>[^,]+?)\s*,\s*(?P<second>[A-Za-z_][A-Za-z0-9_]*)(?:\s*,\s*[^)]*)?\)',
    re.DOTALL | re.IGNORECASE,
)
COMMAND_EXEC_SINGLE_ARG_RE = re.compile(
    r'\.exec\s*\(\s*(?P<first>(?:[^()]|\([^)]*\))+?)\s*\)',
    re.DOTALL | re.IGNORECASE,
)
COMMAND_LIST_USAGE_RE = re.compile(
    r'(?:new\s+ProcessBuilder\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)|\.command\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\))',
    re.IGNORECASE,
)
COMMAND_EXPR_USAGE_RE = re.compile(
    r'(?:new\s+ProcessBuilder\s*\(\s*(?P<ctor>[^)]*?)\s*\)|\.command\s*\(\s*(?P<call>[^)]*?)\s*\))',
    re.DOTALL | re.IGNORECASE,
)
BUILDER_TOSTRING_RE = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)\.toString\s*\(\s*\)', re.IGNORECASE)
LDAP_PATTERNS = (
    re.compile(r"InitialDirContext", re.IGNORECASE),
    re.compile(r"DirContext", re.IGNORECASE),
    re.compile(r"\.search\s*\(", re.IGNORECASE),
)
XPATH_PATTERNS = (
    re.compile(r"XPathFactory\s*\.\s*newInstance\s*\(", re.IGNORECASE),
    re.compile(r"\.evaluate\s*\(", re.IGNORECASE),
)
SQL_PREPARE_CALL_RE = re.compile(r"prepareCall\s*\(", re.IGNORECASE)
SQL_PREPARE_STATEMENT_RE = re.compile(r"prepareStatement\s*\(", re.IGNORECASE)
SQL_CALLABLE_STATEMENT_RE = re.compile(r"CallableStatement", re.IGNORECASE)
SQL_EXECUTE_CALL_PATTERNS = (
    re.compile(r"\.executeQuery\s*\(", re.IGNORECASE),
    re.compile(r"\.executeUpdate\s*\(", re.IGNORECASE),
    re.compile(r"\.execute\s*\(", re.IGNORECASE),
    re.compile(r"JDBCtemplate\s*\.\s*(?:execute|queryForMap|queryForRowSet|queryForList|update)\s*\(", re.IGNORECASE),
)
STRING_BUILDER_RE = re.compile(r"String(?:Builder|Buffer)", re.IGNORECASE)
APPEND_CALL_RE = re.compile(r"\.append\s*\(", re.IGNORECASE)
ARRAY_LITERAL_RE = re.compile(r"\{[^{}]*[A-Za-z_][A-Za-z0-9_]*[^{}]*\}")
SIMPLE_ASSIGNMENT_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^;]+);", re.DOTALL)
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
STRING_CONCAT_PATTERNS = (
    re.compile(r'"[^"\n]*"\s*\+\s*[A-Za-z_(]', re.IGNORECASE),
    re.compile(r"[A-Za-z_][A-Za-z0-9_.)]*\s*\+\s*\"[^\n]*\"", re.IGNORECASE),
    re.compile(r"[A-Za-z_][A-Za-z0-9_.)]*\s*\+\s*[A-Za-z_][A-Za-z0-9_.(]*", re.IGNORECASE),
)


class SourceSanitizer:
    @staticmethod
    def strip_comments(source_code: str, *, strip_string_literals: bool) -> str:
        if not source_code:
            return source_code

        sanitized: list[str] = []
        in_block_comment = False
        in_string = False
        in_char = False
        escaped = False
        quote_char = ""
        index = 0

        while index < len(source_code):
            char = source_code[index]
            nxt = source_code[index + 1] if index + 1 < len(source_code) else ""

            if in_block_comment:
                if char == "*" and nxt == "/":
                    sanitized.extend("  ")
                    in_block_comment = False
                    index += 2
                    continue
                sanitized.append("\n" if char == "\n" else " ")
                index += 1
                continue

            if in_string or in_char:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote_char:
                    if in_string:
                        in_string = False
                    else:
                        in_char = False
                if strip_string_literals:
                    sanitized.append("\n" if char == "\n" else " ")
                else:
                    sanitized.append(char)
                index += 1
                continue

            if char == "/" and nxt == "/":
                sanitized.extend("  ")
                index += 2
                while index < len(source_code) and source_code[index] != "\n":
                    sanitized.append(" ")
                    index += 1
                continue

            if char == "/" and nxt == "*":
                sanitized.extend("  ")
                in_block_comment = True
                index += 2
                continue

            if char == '"':
                in_string = True
                quote_char = '"'
                sanitized.append(" " if strip_string_literals else char)
                index += 1
                continue

            if char == "'":
                in_char = True
                quote_char = "'"
                sanitized.append(" " if strip_string_literals else char)
                index += 1
                continue

            sanitized.append(char)
            index += 1

        return "".join(sanitized)

    @staticmethod
    def strip_comments_and_string_literals(source_code: str) -> str:
        return SourceSanitizer.strip_comments(source_code, strip_string_literals=True)

    @staticmethod
    def strip_comments_and_annotations(source_code: str) -> str:
        without_comments = SourceSanitizer.strip_comments(source_code, strip_string_literals=False)
        return re.sub(r"(?m)^\s*@[A-Za-z_][A-Za-z0-9_$.]*(?:\([^)]*\))?\s*$", "", without_comments)


@dataclass(frozen=True)
class AssignmentState:
    tainted_vars: set[str]
    string_constants: Dict[str, str]


class AssignmentStateAnalyzer:
    def __init__(self, taint_patterns=UNTRUSTED_INPUT_PATTERNS) -> None:
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
            case_match = re.search(
                rf"case\s+'{re.escape(constant)}'\s*:(.*?)(?=break;|case\s+'|default:|\Z)",
                body,
                re.DOTALL,
            )
            if case_match:
                return case_match.group(1)
            default_match = re.search(r"default\s*:(.*?)(?=break;|\Z)", body, re.DOTALL)
            return default_match.group(1) if default_match else ""

        return SWITCH_BLOCK_RE.sub(_replace, source_code)


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


class PathSafetyAnalyzer:
    def __init__(self) -> None:
        self._assignment_analyzer = AssignmentStateAnalyzer()

    def safe_constant_override_detected(self, source_code: str) -> bool:
        state = self._assignment_analyzer.analyze(source_code)
        sink_vars: set[str] = set()
        for pattern in PATH_SINK_VARIABLE_PATTERNS:
            for match in pattern.finditer(source_code):
                sink_vars.add(match.group(1))
        if not sink_vars:
            return False
        if sink_vars & set(state.string_constants):
            return True
        for match in SIMPLE_ASSIGNMENT_RE.finditer(source_code):
            var = match.group(1)
            if var not in sink_vars:
                continue
            referenced = self._assignment_analyzer.referenced_variables(match.group(2))
            if referenced & state.tainted_vars:
                continue
            if referenced & set(state.string_constants):
                return True
        return False

    def sink_references_tainted_data(self, source_code: str) -> bool:
        state = self._assignment_analyzer.analyze(source_code)
        for pattern in PATH_SINK_VARIABLE_PATTERNS:
            for match in pattern.finditer(source_code):
                if match.group(1) in state.tainted_vars:
                    return True
        return any(pattern.search(source_code) for pattern in DIRECT_PATH_UNTRUSTED_PATTERNS)


class PolicyIndicatorAnalyzer:
    def __init__(self) -> None:
        self._path_safety = PathSafetyAnalyzer()
        self._command_flow = CommandFlowAnalyzer()

    @staticmethod
    def empty_flags() -> Dict[str, bool]:
        return {
            "md5_literal": False,
            "md5_variable": False,
            "md5_detected": False,
            "weak_cipher_literal": False,
            "weak_cipher_detected": False,
            "insecure_random_detected": False,
            "sha1prng_detected": False,
            "path_traversal_detected": False,
            "path_safe_constant_detected": False,
            "command_exec_string_tainted": False,
            "command_exec_args_tainted": False,
            "command_env_only_tainted": False,
            "command_injection_detected": False,
            "ldap_injection_detected": False,
            "xpath_injection_detected": False,
            "sql_prepare_call_detected": False,
            "sql_callable_statement_detected": False,
            "sql_dynamic_query_detected": False,
        }

    def analyze(self, source_code: str) -> Dict[str, bool]:
        if not source_code:
            return self.empty_flags()

        untrusted_input_detected = any(pattern.search(source_code) for pattern in UNTRUSTED_INPUT_PATTERNS)
        sql_untrusted_input_detected = any(pattern.search(source_code) for pattern in SQL_UNTRUSTED_INPUT_PATTERNS)
        path_ldap_untrusted_input_detected = any(
            pattern.search(source_code) for pattern in PATH_LDAP_UNTRUSTED_INPUT_PATTERNS
        )
        builder_append_detected = bool(STRING_BUILDER_RE.search(source_code) and APPEND_CALL_RE.search(source_code))
        dynamic_construction_detected = builder_append_detected or any(
            pattern.search(source_code) for pattern in STRING_CONCAT_PATTERNS
        )
        md5_literal = False
        md5_variable = False
        weak_cipher_literal = False
        insecure_random_detected = False
        sha1prng_detected = False

        for match in MD5_LITERAL_RE.findall(source_code):
            if match.strip().lower() == "md5":
                md5_literal = True
                break

        assignments = {}
        for var, value in STRING_ASSIGN_RE.findall(source_code):
            if value.strip().lower() == "md5":
                assignments[var] = value

        if assignments:
            for var in MD5_VAR_RE.findall(source_code):
                if var in assignments:
                    md5_variable = True
                    break

        for algo in CIPHER_LITERAL_RE.findall(source_code):
            lowered = algo.strip().lower()
            if "des" in lowered or "rc4" in lowered or "ecb" in lowered:
                weak_cipher_literal = True
                break

        source_without_literals = SourceSanitizer.strip_comments_and_string_literals(source_code)

        if any(pattern.search(source_without_literals) for pattern in INSECURE_RANDOM_PATTERNS):
            insecure_random_detected = True

        if SHA1_PRNG_RE.search(source_code):
            sha1prng_detected = True

        path_dynamic_usage_detected = any(pattern.search(source_code) for pattern in PATH_DYNAMIC_CONSTRUCTION_PATTERNS) or any(
            pattern.search(source_code) for pattern in PATH_DYNAMIC_ARGUMENT_PATTERNS
        )
        path_safe_constant_detected = self._path_safety.safe_constant_override_detected(source_code)
        path_traversal_detected = (
            path_ldap_untrusted_input_detected
            and any(pattern.search(source_code) for pattern in PATH_TRAVERSAL_PATTERNS)
            and path_dynamic_usage_detected
            and not path_safe_constant_detected
        )
        command_analysis = self._command_flow.analyze(source_code)
        command_exec_string_tainted = command_analysis.command_exec_string_tainted
        command_exec_args_tainted = command_analysis.command_exec_args_tainted
        command_env_only_tainted = command_analysis.command_env_only_tainted
        command_injection_detected = command_exec_string_tainted or command_exec_args_tainted
        ldap_injection_detected = (
            path_ldap_untrusted_input_detected
            and any(pattern.search(source_code) for pattern in LDAP_PATTERNS[:2])
            and bool(LDAP_PATTERNS[2].search(source_code))
            and dynamic_construction_detected
        )
        xpath_injection_detected = (
            untrusted_input_detected
            and all(pattern.search(source_code) for pattern in XPATH_PATTERNS)
            and dynamic_construction_detected
        )
        sql_prepare_call_detected = bool(SQL_PREPARE_CALL_RE.search(source_code))
        sql_prepare_statement_detected = bool(SQL_PREPARE_STATEMENT_RE.search(source_code))
        sql_callable_statement_detected = bool(SQL_CALLABLE_STATEMENT_RE.search(source_code))
        sql_execution_detected = sql_prepare_call_detected or sql_prepare_statement_detected or any(
            pattern.search(source_code) for pattern in SQL_EXECUTE_CALL_PATTERNS
        )
        sql_dynamic_query_detected = bool(
            sql_untrusted_input_detected and sql_execution_detected and dynamic_construction_detected
        )

        md5_detected = md5_literal or md5_variable
        weak_cipher_detected = weak_cipher_literal
        return {
            "md5_literal": md5_literal,
            "md5_variable": md5_variable,
            "md5_detected": md5_detected,
            "weak_cipher_literal": weak_cipher_literal,
            "weak_cipher_detected": weak_cipher_detected,
            "insecure_random_detected": insecure_random_detected,
            "sha1prng_detected": sha1prng_detected,
            "path_traversal_detected": path_traversal_detected,
            "path_safe_constant_detected": path_safe_constant_detected,
            "command_exec_string_tainted": command_exec_string_tainted,
            "command_exec_args_tainted": command_exec_args_tainted,
            "command_env_only_tainted": command_env_only_tainted,
            "command_injection_detected": command_injection_detected,
            "ldap_injection_detected": ldap_injection_detected,
            "xpath_injection_detected": xpath_injection_detected,
            "sql_prepare_call_detected": sql_prepare_call_detected,
            "sql_callable_statement_detected": sql_callable_statement_detected,
            "sql_dynamic_query_detected": sql_dynamic_query_detected,
        }


DEFAULT_POLICY_ANALYZER = PolicyIndicatorAnalyzer()
