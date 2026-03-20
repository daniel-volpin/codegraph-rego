from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict

from codegraph.common.snippet_utils import extract_code_snippet, extract_snippet_by_lines
from codegraph.policy.source_analysis_core import AssignmentStateAnalyzer, PATH_LDAP_UNTRUSTED_INPUT_PATTERNS

CALL_ASSIGNMENT_RE = re.compile(
    r"(?:final\s+)?(?:[A-Za-z_][A-Za-z0-9_$.<>\[\]]+\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:(?:new\s+[A-Za-z_][A-Za-z0-9_$.<>]*\(\)|[A-Za-z_][A-Za-z0-9_$.<>]*)\s*\.\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\(",
    re.DOTALL,
)
CALL_ASSIGNMENT_WITH_ARGS_RE = re.compile(
    r"(?:final\s+)?(?:[A-Za-z_][A-Za-z0-9_$.<>\[\]]+\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:(?:new\s+[A-Za-z_][A-Za-z0-9_$.<>]*\(\)|[A-Za-z_][A-Za-z0-9_$.<>]*)\s*\.\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\(([^;]*?)\)\s*;",
    re.DOTALL,
)
METHOD_DECL_RE = re.compile(
    r"(?:public|protected|private)?\s*(?:static\s+)?(?:final\s+)?[A-Za-z_][A-Za-z0-9_$.<>\[\]]+\s+[A-Za-z_][A-Za-z0-9_]*\s*\(([^)]*)\)",
    re.DOTALL,
)
RETURN_RE = re.compile(r"return\s+([^;]+);", re.DOTALL)
MAP_PUT_LITERAL_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)\.put\(\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\)', re.DOTALL)
MAP_GET_LITERAL_RE = re.compile(r'(?:\([^)]+\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\.get\(\s*"([^"]+)"\s*\)', re.DOTALL)
MAP_PUT_VALUE_RE = re.compile(
    r'([A-Za-z_][A-Za-z0-9_]*)\.put\(\s*"([^"]+)"\s*,\s*([^;]+?)\s*\)\s*;',
    re.DOTALL,
)
MAP_GET_ASSIGNMENT_RE = re.compile(
    r'([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:\([^)]+\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\.get\(\s*"([^"]+)"\s*\)\s*;',
    re.DOTALL,
)
LIST_ADD_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)\.add\(\s*([^;]+?)\s*\)\s*;', re.DOTALL)
LIST_REMOVE_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)\.remove\(\s*(\d+)\s*\)\s*;', re.DOTALL)
LIST_GET_ASSIGNMENT_RE = re.compile(
    r'([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:\([^)]+\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\.get\(\s*(\d+)\s*\)\s*;',
    re.DOTALL,
)
ARRAY_ASSIGNMENT_RE = re.compile(
    r'(?:[A-Za-z_][A-Za-z0-9_$.<>\[\]]+\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:new\s+[A-Za-z_][A-Za-z0-9_$.<>\[\]]*\[\]\s*)?\{(.*?)\}\s*;',
    re.DOTALL,
)
FILTER_ASSIGNMENT_TEMPLATE = r"\bfilter\w*\s*=\s*[^;]*\b%s\b"
PATH_ASSIGNMENT_TEMPLATE = r"\b(?:file|path|uri)\w*\s*=\s*[^;]*\b%s\b"
PATH_DIRECT_USAGE_TEMPLATE = (
    r"(?:new\s+java\.io\.(?:File|FileInputStream|FileOutputStream|FileReader)\s*\([^;]*\b%s\b"
    r"|Paths\s*\.\s*get\s*\([^;]*\b%s\b"
    r"|new\s+java\.net\.URI\s*\([^;]*\b%s\b)"
)
XPATH_ASSIGNMENT_TEMPLATE = r"\b(?:expr|expression|query|xpath)\w*\s*=\s*[^;]*\b%s\b"
XPATH_USAGE_TEMPLATE = r"(?:\.evaluate\s*\(\s*[^,;)]*\b%s\b|\.compile\s*\(\s*[^;)]*\b%s\b)"
SQL_ASSIGNMENT_TEMPLATE = r"\bsql\w*\s*=\s*[^;]*\b%s\b"
SQL_USAGE_TEMPLATE = (
    r"(?:prepareStatement\s*\(\s*[^,;)]*\b%s\b"
    r"|prepareCall\s*\(\s*[^,;)]*\b%s\b"
    r"|execute(?:Query|Update)?\s*\(\s*[^,;)]*\b%s\b"
    r"|JDBCtemplate\s*\.\s*(?:execute|query|queryForMap|queryForObject|queryForRowSet|queryForList|update|batchUpdate)\s*\(\s*[^,;)]*\b%s\b)"
)
COMMAND_ASSIGNMENT_TEMPLATE = r"\b(?:cmd|command)\w*\s*=\s*[^;]*\b%s\b"
COMMAND_USAGE_TEMPLATE = r"(?:\.exec\s*\(\s*[^,;)]*\b%s\b|\.command\s*\([^;)]*\b%s\b|new\s+ProcessBuilder\s*\([^;)]*\b%s\b)"
COMMAND_LIST_USAGE_RE = re.compile(
    r'(?:new\s+ProcessBuilder\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)|\.command\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\))',
    re.IGNORECASE,
)
COMMAND_EXEC_FIRST_ARG_VAR_RE = re.compile(r'\.exec\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:,|\))', re.IGNORECASE)
COMMAND_EXEC_ENV_ARG_VAR_RE = re.compile(
    r'\.exec\s*\(\s*[^,]+,\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:,|\))',
    re.IGNORECASE,
)
STRING_LITERAL_FULL_RE = re.compile(r'^"([^"\\]*(?:\\.[^"\\]*)*)"$', re.DOTALL)


@dataclass(frozen=True)
class HelperReturnSummary:
    returns_constant_string: bool
    propagates_tainted_input: bool


class HelperMethodAnalyzer:
    def __init__(self) -> None:
        self._assignment_analyzer = AssignmentStateAnalyzer()
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
                if map_match and map_match.group(1) in map_constants and map_match.group(2) in map_constants[map_match.group(1)]:
                    returns_constant = True
                elif self._assignment_analyzer.referenced_variables(expr) & state.tainted_vars:
                    propagates_taint = True
        return HelperReturnSummary(
            returns_constant_string=returns_constant,
            propagates_tainted_input=propagates_taint,
        )

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
    def _map_string_constants(source_code: str) -> Dict[str, Dict[str, str]]:
        values: Dict[str, Dict[str, str]] = {}
        for map_name, key, value in MAP_PUT_LITERAL_RE.findall(source_code):
            values.setdefault(map_name, {})[key] = value
        return values


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
        entries: Dict[str, Dict[str, str]] = {}
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
        items: Dict[str, list[str]] = {}
        for list_name, raw_value in LIST_ADD_RE.findall(source_code):
            resolved = self._resolve_expr(raw_value.strip(), assignment_analyzer, state)
            if resolved is not None:
                items.setdefault(list_name, []).append(resolved)
        for list_name, raw_index in LIST_REMOVE_RE.findall(source_code):
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

        return LIST_GET_ASSIGNMENT_RE.sub(_replace, source_code)

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


class DirectCallSummaryBuilder:
    def __init__(self) -> None:
        self._method_analyzer = HelperMethodAnalyzer()
        self._assignment_analyzer = AssignmentStateAnalyzer(PATH_LDAP_UNTRUSTED_INPUT_PATTERNS)

    def build(
        self,
        *,
        current_source: str,
        method_snapshot: Dict[str, Any],
        method_index: Dict[str, Dict[str, Any]],
    ) -> Dict[str, Any]:
        safe_vars: list[str] = []
        tainted_vars: list[str] = []
        path_safe_vars: list[str] = []
        path_tainted_vars: list[str] = []
        ldap_safe_vars: list[str] = []
        ldap_tainted_vars: list[str] = []
        state = self._assignment_analyzer.analyze(current_source)
        call_signatures = method_snapshot.get("calls") or []
        for assigned_var, method_name, raw_args in CALL_ASSIGNMENT_WITH_ARGS_RE.findall(current_source):
            is_untrusted_source_call = method_name.lower() in {
                "getparameter",
                "getheader",
                "getquerystring",
                "getcookies",
                "getparametermap",
                "getparametervalues",
                "getparameternames",
                "getheaders",
                "gettheparameter",
            }
            if is_untrusted_source_call:
                continue
            arg_refs = self._assignment_analyzer.referenced_variables(raw_args)
            arg_has_tainted_input = bool(
                any(pattern.search(raw_args) for pattern in PATH_LDAP_UNTRUSTED_INPUT_PATTERNS)
                or arg_refs & state.tainted_vars
            )
            arg_is_safe_constant = bool(
                raw_args.strip()
                and not arg_has_tainted_input
                and (
                    STRING_LITERAL_FULL_RE.match(raw_args.strip())
                    or arg_refs <= set(state.string_constants)
                )
            )
            callee_snapshot = self._resolve_called_method(
                method_name=method_name,
                call_signatures=call_signatures,
                current_class_fqn=method_snapshot.get("class_fqn"),
                current_file_path=method_snapshot.get("file_path"),
                method_index=method_index,
            )
            if not callee_snapshot:
                if arg_is_safe_constant:
                    path_safe_vars.append(assigned_var)
                    ldap_safe_vars.append(assigned_var)
                continue
            summary = self._method_analyzer.summarize(self._read_method_source(callee_snapshot))
            if summary.returns_constant_string:
                safe_vars.append(assigned_var)
                path_safe_vars.append(assigned_var)
                ldap_safe_vars.append(assigned_var)
            elif arg_is_safe_constant:
                path_safe_vars.append(assigned_var)
                ldap_safe_vars.append(assigned_var)
            if summary.propagates_tainted_input:
                tainted_vars.append(assigned_var)
                if arg_has_tainted_input:
                    path_tainted_vars.append(assigned_var)
                if arg_has_tainted_input:
                    ldap_tainted_vars.append(assigned_var)
        safe_vars = sorted(set(safe_vars))
        tainted_vars = sorted(set(tainted_vars))
        path_safe_vars = sorted(set(path_safe_vars))
        path_tainted_vars = sorted(set(path_tainted_vars))
        ldap_safe_vars = sorted(set(ldap_safe_vars))
        ldap_tainted_vars = sorted(set(ldap_tainted_vars))
        return {
            "safe_constant_return_vars": safe_vars,
            "tainted_return_vars": tainted_vars,
            "safe_constant_return_used_in_path_sink": self._vars_used_in_path_sink(current_source, path_safe_vars),
            "tainted_return_used_in_path_sink": self._vars_used_in_path_sink(current_source, path_tainted_vars),
            "safe_constant_return_used_in_ldap_filter": self._vars_used_in_template(current_source, ldap_safe_vars, FILTER_ASSIGNMENT_TEMPLATE),
            "tainted_return_used_in_ldap_filter": self._vars_used_in_template(current_source, ldap_tainted_vars, FILTER_ASSIGNMENT_TEMPLATE),
            "safe_constant_return_used_in_xpath_query": self._vars_used_in_xpath(current_source, safe_vars),
            "safe_constant_return_used_in_sql_query": self._vars_used_in_sql(current_source, safe_vars),
            "safe_constant_return_used_in_command_sink": self._vars_used_in_command(current_source, safe_vars),
            "tainted_return_used_in_xpath_query": self._vars_used_in_xpath(current_source, tainted_vars),
            "tainted_return_used_in_sql_query": self._vars_used_in_sql(current_source, tainted_vars),
            "tainted_return_used_in_command_sink": self._vars_used_in_command(current_source, tainted_vars),
            "analyzed_call_count": len(safe_vars) + len(tainted_vars),
        }

    @staticmethod
    def _resolve_called_method(
        *,
        method_name: str,
        call_signatures: list[str],
        current_class_fqn: str | None,
        current_file_path: str | None,
        method_index: Dict[str, Dict[str, Any]],
    ) -> Dict[str, Any] | None:
        candidates = [sig for sig in call_signatures if sig and _method_name_from_signature(sig) == method_name]
        if not candidates:
            return DirectCallSummaryBuilder._resolve_same_file_method(
                method_name=method_name,
                current_class_fqn=current_class_fqn,
                current_file_path=current_file_path,
                method_index=method_index,
            )
        if len(candidates) == 1:
            return method_index.get(candidates[0])
        if current_class_fqn:
            nested_prefix = f"{current_class_fqn}$"
            for signature in candidates:
                snapshot = method_index.get(signature)
                class_fqn = snapshot.get("class_fqn") if snapshot else None
                if isinstance(class_fqn, str) and class_fqn.startswith(nested_prefix):
                    return snapshot
            for signature in candidates:
                snapshot = method_index.get(signature)
                if snapshot and snapshot.get("class_fqn") == current_class_fqn:
                    return snapshot
        for signature in candidates:
            snapshot = method_index.get(signature)
            if snapshot and snapshot.get("class_fqn") == current_class_fqn:
                return snapshot
        return method_index.get(candidates[0]) or DirectCallSummaryBuilder._resolve_same_file_method(
            method_name=method_name,
            current_class_fqn=current_class_fqn,
            current_file_path=current_file_path,
            method_index=method_index,
        )

    @staticmethod
    def _resolve_same_file_method(
        *,
        method_name: str,
        current_class_fqn: str | None,
        current_file_path: str | None,
        method_index: Dict[str, Dict[str, Any]],
    ) -> Dict[str, Any] | None:
        if not current_file_path:
            return None
        candidates = [
            snapshot
            for snapshot in method_index.values()
            if snapshot.get("name") == method_name and snapshot.get("file_path") == current_file_path
        ]
        if not candidates:
            return None
        if current_class_fqn:
            nested_prefix = f"{current_class_fqn}$"
            for snapshot in candidates:
                class_fqn = snapshot.get("class_fqn")
                if isinstance(class_fqn, str) and class_fqn.startswith(nested_prefix):
                    return snapshot
            for snapshot in candidates:
                if snapshot.get("class_fqn") == current_class_fqn:
                    return snapshot
        return candidates[0]

    @staticmethod
    def _read_method_source(method_snapshot: Dict[str, Any]) -> str:
        file_path = method_snapshot.get("file_path")
        if not file_path:
            return ""
        path = Path(file_path)
        if not path.is_file():
            return ""
        source_code = extract_snippet_by_lines(
            path.as_posix(),
            method_snapshot.get("start_line"),
            method_snapshot.get("end_line"),
            padding=2,
        )
        if not source_code and method_snapshot.get("name"):
            return extract_code_snippet(path.as_posix(), method_snapshot.get("name", ""))
        return source_code

    @staticmethod
    def _vars_used_in_template(source_code: str, vars_to_check: list[str], template: str) -> bool:
        for var in vars_to_check:
            if re.search(template % re.escape(var), source_code, re.IGNORECASE):
                return True
        return False

    @staticmethod
    def _vars_used_in_path_sink(source_code: str, vars_to_check: list[str]) -> bool:
        for var in vars_to_check:
            if re.search(PATH_ASSIGNMENT_TEMPLATE % re.escape(var), source_code, re.IGNORECASE):
                return True
            if re.search(
                PATH_DIRECT_USAGE_TEMPLATE % (re.escape(var), re.escape(var), re.escape(var)),
                source_code,
                re.IGNORECASE,
            ):
                return True
        return False

    @staticmethod
    def _vars_used_in_xpath(source_code: str, vars_to_check: list[str]) -> bool:
        for var in vars_to_check:
            if re.search(XPATH_ASSIGNMENT_TEMPLATE % re.escape(var), source_code, re.IGNORECASE):
                return True
            if re.search(XPATH_USAGE_TEMPLATE % (re.escape(var), re.escape(var)), source_code, re.IGNORECASE):
                return True
        return False

    @staticmethod
    def _vars_used_in_sql(source_code: str, vars_to_check: list[str]) -> bool:
        for var in vars_to_check:
            if re.search(SQL_ASSIGNMENT_TEMPLATE % re.escape(var), source_code, re.IGNORECASE):
                return True
            if re.search(
                SQL_USAGE_TEMPLATE
                % (re.escape(var), re.escape(var), re.escape(var), re.escape(var)),
                source_code,
                re.IGNORECASE,
            ):
                return True
        return False

    @staticmethod
    def _vars_used_in_command(source_code: str, vars_to_check: list[str]) -> bool:
        if not vars_to_check:
            return False
        payload_lists, payload_arrays = DirectCallSummaryBuilder._command_payload_vars(source_code)
        for var in vars_to_check:
            if re.search(COMMAND_ASSIGNMENT_TEMPLATE % re.escape(var), source_code, re.IGNORECASE):
                return True
            if re.search(
                COMMAND_USAGE_TEMPLATE % (re.escape(var), re.escape(var), re.escape(var)),
                source_code,
                re.IGNORECASE,
            ):
                return True
            for list_name, expr in LIST_ADD_RE.findall(source_code):
                if list_name in payload_lists and re.search(rf"\b{re.escape(var)}\b", expr):
                    return True
            for array_name, entries in ARRAY_ASSIGNMENT_RE.findall(source_code):
                if array_name in payload_arrays and re.search(rf"\b{re.escape(var)}\b", entries):
                    return True
        return False

    @staticmethod
    def _command_payload_vars(source_code: str) -> tuple[set[str], set[str]]:
        list_variables = {list_name for list_name, _expr in LIST_ADD_RE.findall(source_code)}
        payload_call_vars = {
            candidate
            for groups in COMMAND_LIST_USAGE_RE.findall(source_code)
            for candidate in groups
            if candidate
        }
        payload_lists = {candidate for candidate in payload_call_vars if candidate in list_variables}
        payload_arrays = (
            payload_call_vars
            | set(COMMAND_EXEC_FIRST_ARG_VAR_RE.findall(source_code))
            | set(COMMAND_EXEC_ENV_ARG_VAR_RE.findall(source_code))
        )
        return payload_lists, payload_arrays


def _method_name_from_signature(signature: str) -> str:
    head = signature.split("(")[0]
    return head.rsplit(".", 1)[-1]
