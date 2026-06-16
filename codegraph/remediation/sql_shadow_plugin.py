from __future__ import annotations

# pyright: reportMissingImports=false, reportMissingTypeStubs=false
import hashlib
import json
import re
from pathlib import Path
from typing import Any, cast

import javalang  # type: ignore[import-untyped]
from javalang.tree import (  # type: ignore[import-untyped]
    BinaryOperation,
    Literal,
    LocalVariableDeclaration,
    MemberReference,
    MethodDeclaration,
    MethodInvocation,
)

from codegraph.remediation.patch_compiler import compile_repair_intent
from codegraph.remediation.plugin_types import (
    PipelineVerificationContract,
    PluginDescriptor,
    PluginProposal,
    RepairPatternContract,
)
from codegraph.remediation.repair_intent import (
    RepairIntent,
    RepairIntentKind,
    RepairOperation,
    SourceSpan,
    StructuredEditOp,
)
from codegraph.remediation.result_models import (
    ArtifactKind,
    Disposition,
    LifecycleReasonCode,
    PatchArtifact,
    StructuredRepairPlanArtifact,
    TransformationStrategy,
    ValidatorResult,
    ValidatorState,
)
from codegraph.remediation.verification import BuildRequirement


def _decode_java_string(value: str) -> str:
    inner = value[1:-1] if len(value) >= 2 and value[0] == '"' and value[-1] == '"' else value
    return bytes(inner, "utf-8").decode("unicode_escape")


def _flatten_concat(node: Any) -> list[Any]:
    if isinstance(node, BinaryOperation) and node.operator == "+":
        return _flatten_concat(node.operandl) + _flatten_concat(node.operandr)
    return [node]


def _member_ref_text(node: MemberReference) -> str | None:
    if node.qualifier:
        return None
    return node.member


def _normalize_file_path(file_path: str) -> str:
    path = Path(file_path)
    parts = list(path.parts)
    for marker in ("src", "uploaded_code"):
        if marker in parts:
            return Path(*parts[parts.index(marker) :]).as_posix()
    return path.name or path.as_posix().lstrip("/")


class JdbcSqlShadowPlugin:
    descriptor = PluginDescriptor(
        plugin_id="jdbc-sql-shadow",
        plugin_version="1.0.0",
        supported_languages=["java"],
        supported_rule_ids=["ISO-A.8-SQL-INJECTION"],
        patterns=[
            RepairPatternContract(
                pattern_id="SQL-VAL-001",
                pattern_version="1.0.0",
                repair_patterns=[
                    "method-local sql variable construction",
                    "value-only concatenation",
                ],
                required_evidence=["exact_method_source", "file_path", "target_method"],
                transformation_strategy=TransformationStrategy.TYPED_STRUCTURED_EDITS,
                max_edit_scope_lines=4,
                mandatory_semantic_validators=[
                    "sql.constant_structure",
                    "sql.placeholder_count",
                    "sql.binding_order",
                    "sql.binding_types",
                    "sql.executed_prepared_statement",
                    "sql.dynamic_sink_removed",
                    "sql.no_forbidden_dynamic_clause",
                    "sql.edit_scope",
                    "sql.no_invented_symbols",
                ],
                pipeline_verification=PipelineVerificationContract(
                    build_requirement=BuildRequirement.IF_BUILD_SYSTEM_PRESENT,
                    require_parse=True,
                    require_policy_recheck=True,
                ),
                auto_apply_capable=True,
            ),
            RepairPatternContract(
                pattern_id="SQL-VAL-002",
                pattern_version="1.0.0",
                repair_patterns=[
                    "statement execute conversion",
                    "prepared statement substitution",
                ],
                required_evidence=["exact_method_source", "file_path", "target_method"],
                transformation_strategy=TransformationStrategy.TYPED_STRUCTURED_EDITS,
                max_edit_scope_lines=4,
                mandatory_semantic_validators=[
                    "sql.constant_structure",
                    "sql.placeholder_count",
                    "sql.binding_order",
                    "sql.binding_types",
                    "sql.executed_prepared_statement",
                    "sql.dynamic_sink_removed",
                    "sql.no_forbidden_dynamic_clause",
                    "sql.edit_scope",
                    "sql.no_invented_symbols",
                ],
                pipeline_verification=PipelineVerificationContract(
                    build_requirement=BuildRequirement.IF_BUILD_SYSTEM_PRESENT,
                    require_parse=True,
                    require_policy_recheck=True,
                ),
                auto_apply_capable=True,
            ),
        ],
    )

    _BINDING_METHODS = {
        "String": "setString",
        "int": "setInt",
        "Integer": "setInt",
        "long": "setLong",
        "Long": "setLong",
        "boolean": "setBoolean",
        "Boolean": "setBoolean",
        "double": "setDouble",
        "Double": "setDouble",
        "float": "setFloat",
        "Float": "setFloat",
        "short": "setShort",
        "Short": "setShort",
        "byte": "setByte",
        "Byte": "setByte",
    }

    def supports(self, *, rule_id: str, language: str) -> bool:
        return rule_id in self.descriptor.supported_rule_ids and language in self.descriptor.supported_languages

    def propose(self, context: dict[str, Any]) -> PluginProposal:
        source = str(context.get("exact_method_source") or "")
        target_method = str(context.get("target_method") or "unknown")
        file_path = str(context.get("file_path") or "unknown")
        normalized_file_path = _normalize_file_path(file_path)
        if not source.strip():
            return self._plan_fallback(
                summary="Exact method source is required for bounded SQL repair.",
                reason=LifecycleReasonCode.INSUFFICIENT_EVIDENCE,
            )

        method, line_offset = self._parse_method(source)
        if method is None:
            return self._plan_fallback(
                summary="Method snippet could not be parsed for deterministic SQL transformation.",
                reason=LifecycleReasonCode.INSUFFICIENT_EVIDENCE,
            )

        symbol_types = self._collect_symbol_types(method)
        match = self._find_sql_candidate(method, source.splitlines(), symbol_types, line_offset)
        if match is None:
            return self._plan_fallback(
                summary="SQL query shape is outside the bounded JDBC parameterization patterns.",
                reason=LifecycleReasonCode.UNSUPPORTED_REPAIR_PATTERN,
            )
        if match.get("reason_code") is not None:
            reason_code = match["reason_code"]
            summary = str(match.get("summary") or "SQL remediation candidate was rejected.")
            return self._plan_fallback(summary=summary, reason=reason_code)

        method_lines = source.splitlines()
        operations: list[RepairOperation] = []
        for edit in match["edits"]:
            operations.append(cast(RepairOperation, StructuredEditOp(**edit)))
        intent = RepairIntent(
            kind=RepairIntentKind.STRUCTURED_EDIT,
            rule_id="ISO-A.8-SQL-INJECTION",
            support_tier="manual",
            target=SourceSpan(file_path=normalized_file_path, method_signature=target_method),
            operations=operations,
        )
        compiled_edits = compile_repair_intent(intent, method_lines)
        pattern = next(pattern for pattern in self.descriptor.patterns if pattern.pattern_id == match["pattern_id"])
        reproducibility_key = self._reproducibility_key(
            file_path=file_path,
            target_method=target_method,
            source=source,
            pattern_id=pattern.pattern_id,
            pattern_version=pattern.pattern_version,
            details=match["repro_inputs"],
        )
        return PluginProposal(
            artifact_kind=ArtifactKind.PATCH,
            disposition=Disposition.REVIEW_REQUIRED,
            repair_intent=intent,
            patch_pattern=pattern,
            reason_codes=[],
            evidence_complete=True,
            project_policy_dependency_resolved=True,
            details={
                **match,
                "reproducibility_key": reproducibility_key,
                "patch_artifact": PatchArtifact(
                    target_file=normalized_file_path,
                    anchor_method=target_method,
                    edits=compiled_edits,
                ).model_dump(mode="json"),
            },
        )

    def evaluate_semantics(
        self,
        *,
        context: dict[str, Any],
        proposal: PluginProposal,
        updated_method_source: str | None,
    ) -> list[ValidatorResult]:
        if proposal.artifact_kind != ArtifactKind.PATCH:
            return []
        if proposal.patch_pattern is None or proposal.repair_intent is None:
            return [
                ValidatorResult(
                    validator_id="sql.plugin_contract",
                    state=ValidatorState.ERROR,
                    required=True,
                    message="Patch proposals must include both patch_pattern and repair_intent.",
                )
            ]
        details = proposal.details
        bindings = list(details.get("bindings") or [])
        placeholder_count = int(details.get("placeholder_count") or 0)
        statement_var = str(details.get("statement_var") or "stmt")
        method_source = updated_method_source or ""

        max_edit_scope_lines = proposal.patch_pattern.max_edit_scope_lines
        operation_count = len(proposal.repair_intent.operations)
        validators = [
            ValidatorResult(
                validator_id="sql.constant_structure",
                state=ValidatorState.PASS if "+" not in str(details.get("parameterized_sql") or "") else ValidatorState.FAIL,
                required=True,
                details={"sql": details.get("parameterized_sql")},
            ),
            ValidatorResult(
                validator_id="sql.placeholder_count",
                state=ValidatorState.PASS if placeholder_count == len(bindings) else ValidatorState.FAIL,
                required=True,
                details={"placeholders": placeholder_count, "bindings": len(bindings)},
            ),
            ValidatorResult(
                validator_id="sql.binding_order",
                state=ValidatorState.PASS if [binding["index"] for binding in bindings] == list(range(1, len(bindings) + 1)) else ValidatorState.FAIL,
                required=True,
            ),
            ValidatorResult(
                validator_id="sql.binding_types",
                state=ValidatorState.PASS if all(binding.get("binding_method") in self._BINDING_METHODS.values() for binding in bindings) else ValidatorState.FAIL,
                required=True,
            ),
            ValidatorResult(
                validator_id="sql.executed_prepared_statement",
                state=(
                    ValidatorState.PASS
                    if (
                        f"{statement_var}.executeQuery()" in method_source
                        or f"{statement_var}.executeUpdate()" in method_source
                    )
                    else ValidatorState.FAIL
                ),
                required=True,
            ),
            ValidatorResult(
                validator_id="sql.dynamic_sink_removed",
                state=ValidatorState.PASS if not re.search(r"execute(?:Query|Update)\s*\([^)]*\+", method_source) else ValidatorState.FAIL,
                required=True,
            ),
            ValidatorResult(
                validator_id="sql.no_forbidden_dynamic_clause",
                state=ValidatorState.PASS if not any(keyword in str(details.get("rejected_context") or "") for keyword in ["identifier", "order_by", "operator", "clause"]) else ValidatorState.FAIL,
                required=True,
            ),
            ValidatorResult(
                validator_id="sql.edit_scope",
                state=ValidatorState.PASS if operation_count <= max_edit_scope_lines else ValidatorState.FAIL,
                required=True,
            ),
            ValidatorResult(
                validator_id="sql.no_invented_symbols",
                state=ValidatorState.PASS if not details.get("invented_symbols") else ValidatorState.FAIL,
                required=True,
            ),
        ]
        return validators

    def _parse_method(self, source: str) -> tuple[MethodDeclaration | None, int]:
        wrapped = f"class ShadowSqlPlugin {{\n{source}\n}}"
        try:
            tree = javalang.parse.parse(wrapped)
        except Exception:
            return None, 1
        methods = getattr(tree.types[0], "methods", None) or []
        return (methods[0], 1) if methods else (None, 1)

    def _collect_symbol_types(self, method: MethodDeclaration) -> dict[str, str]:
        symbol_types: dict[str, str] = {}
        for parameter in getattr(method, "parameters", []) or []:
            if getattr(parameter, "name", None) and getattr(parameter, "type", None):
                symbol_types[str(parameter.name)] = str(getattr(parameter.type, "name", parameter.type))
        for _, node in method:
            if isinstance(node, LocalVariableDeclaration):
                type_name = str(getattr(node.type, "name", node.type))
                for declarator in node.declarators:
                    symbol_types[str(declarator.name)] = type_name
        return symbol_types

    def _find_sql_candidate(
        self,
        method: MethodDeclaration,
        method_lines: list[str],
        symbol_types: dict[str, str],
        line_offset: int,
    ) -> dict[str, Any] | None:
        query_declarations: dict[str, tuple[Any, int]] = {}
        statement_decl: tuple[str, str, int] | None = None
        statement_decl_error: dict[str, Any] | None = None
        for _, node in method:
            if isinstance(node, LocalVariableDeclaration):
                type_name = str(getattr(node.type, "name", node.type))
                for declarator in node.declarators:
                    line_no = (node.position.line - line_offset) if node.position else None
                    if type_name == "String" and declarator.initializer is not None and line_no is not None:
                        query_declarations[str(declarator.name)] = (declarator.initializer, line_no)
                    if type_name == "Statement" and declarator.initializer is not None and line_no is not None:
                        init = declarator.initializer
                        if isinstance(init, MethodInvocation) and init.member == "createStatement" and init.qualifier:
                            if "(" in str(init.qualifier) or ")" in str(init.qualifier):
                                statement_decl_error = {
                                    "reason_code": LifecycleReasonCode.INSUFFICIENT_EVIDENCE,
                                    "summary": "Connection acquisition is not resolvable without executing helper logic.",
                                }
                            else:
                                statement_decl = (str(declarator.name), str(init.qualifier), line_no)
                        elif isinstance(init, MethodInvocation) and getattr(init, "selectors", None):
                            if any(
                                isinstance(selector, MethodInvocation) and selector.member == "createStatement"
                                for selector in (init.selectors or [])
                            ):
                                statement_decl_error = {
                                    "reason_code": LifecycleReasonCode.INSUFFICIENT_EVIDENCE,
                                    "summary": "Connection acquisition is not resolvable without executing helper logic.",
                                }

        if statement_decl is None:
            if statement_decl_error is not None:
                return statement_decl_error
            return None
        statement_var, connection_expr, statement_line = statement_decl
        if "(" in connection_expr or ")" in connection_expr:
            return {
                "reason_code": LifecycleReasonCode.INSUFFICIENT_EVIDENCE,
                "summary": "Connection acquisition is not resolvable without executing helper logic.",
            }

        for _, node in method:
            if not isinstance(node, MethodInvocation) or node.member not in {"executeQuery", "executeUpdate"}:
                continue
            if node.qualifier != statement_var or len(node.arguments or []) != 1 or node.position is None:
                continue
            execute_line = node.position.line - line_offset
            argument = node.arguments[0]
            query_expr = argument
            query_line = None
            query_var_name = None
            if isinstance(argument, MemberReference):
                query_var_name = _member_ref_text(argument)
                if not query_var_name or query_var_name not in query_declarations:
                    return {
                        "reason_code": LifecycleReasonCode.INSUFFICIENT_EVIDENCE,
                        "summary": "Query text is not recoverable in the same method.",
                    }
                query_expr, query_line = query_declarations[query_var_name]
            pattern = self._parameterize_query(query_expr, symbol_types)
            if pattern.get("reason_code") is not None:
                return pattern

            parameterized_sql = str(pattern["parameterized_sql"])
            bindings = list(pattern["bindings"])
            execute_method = str(node.member)
            statement_original = method_lines[statement_line - 1]
            execute_original = method_lines[execute_line - 1]
            edits: list[dict[str, Any]] = []

            if query_line is not None:
                query_original = method_lines[query_line - 1]
                query_replacement = re.sub(r"=.*;", f' = "{parameterized_sql}";', query_original, count=1)
                edits.append(
                    {
                        "start_line": query_line,
                        "end_line": query_line,
                        "original_lines": [query_original],
                        "replacement_lines": [query_replacement],
                    }
                )
                statement_replacement = re.sub(
                    r"\bStatement\b\s+" + re.escape(statement_var) + r"\s*=\s*.+createStatement\s*\(\s*\)\s*;",
                    f"java.sql.PreparedStatement {statement_var} = {connection_expr}.prepareStatement({query_var_name});",
                    statement_original,
                    count=1,
                )
            else:
                statement_replacement = re.sub(
                    r"\bStatement\b\s+" + re.escape(statement_var) + r"\s*=\s*.+createStatement\s*\(\s*\)\s*;",
                    f'java.sql.PreparedStatement {statement_var} = {connection_expr}.prepareStatement("{parameterized_sql}");',
                    statement_original,
                    count=1,
                )
            edits.append(
                {
                    "start_line": statement_line,
                    "end_line": statement_line,
                    "original_lines": [statement_original],
                    "replacement_lines": [statement_replacement],
                }
            )

            binding_lines = [
                f'{statement_var}.{binding["binding_method"]}({binding["index"]}, {binding["expression"]});'
                for binding in bindings
            ]
            execute_replacement = re.sub(
                r"execute(?:Query|Update)\s*\([^)]*\)",
                f"{execute_method}()",
                execute_original,
                count=1,
            )
            edits.append(
                {
                    "start_line": execute_line,
                    "end_line": execute_line,
                    "original_lines": [execute_original],
                    "replacement_lines": [*binding_lines, execute_replacement],
                }
            )
            return {
                "pattern_id": "SQL-VAL-001" if query_line is not None else "SQL-VAL-002",
                "edits": edits,
                "bindings": bindings,
                "placeholder_count": parameterized_sql.count("?"),
                "parameterized_sql": parameterized_sql,
                "statement_var": statement_var,
                "connection_expr": connection_expr,
                "rejected_context": None,
                "invented_symbols": False,
                "repro_inputs": {
                    "statement_var": statement_var,
                    "connection_expr": connection_expr,
                    "parameterized_sql": parameterized_sql,
                    "bindings": bindings,
                    "execute_method": execute_method,
                },
            }
        return None

    def _parameterize_query(self, query_expr: Any, symbol_types: dict[str, str]) -> dict[str, Any]:
        parts = _flatten_concat(query_expr)
        if not any(not isinstance(part, Literal) for part in parts):
            return {
                "reason_code": LifecycleReasonCode.UNSUPPORTED_REPAIR_PATTERN,
                "summary": "SQL expression is already static or does not require value parameterization.",
            }
        output_parts: list[str] = []
        bindings: list[dict[str, Any]] = []
        strip_leading_quote = False
        for index, part in enumerate(parts):
            if isinstance(part, Literal):
                literal_value = _decode_java_string(str(part.value))
                if strip_leading_quote and literal_value.startswith("'"):
                    literal_value = literal_value[1:]
                strip_leading_quote = False
                output_parts.append(literal_value)
                continue
            if not isinstance(part, MemberReference):
                return {
                    "reason_code": LifecycleReasonCode.INSUFFICIENT_EVIDENCE,
                    "summary": "SQL concatenation includes helper output or unsupported expressions.",
                }
            expression = _member_ref_text(part)
            if not expression or expression not in symbol_types:
                return {
                    "reason_code": LifecycleReasonCode.INSUFFICIENT_EVIDENCE,
                    "summary": "Binding expression type is unresolved in the current method.",
                }
            binding_type = symbol_types[expression]
            binding_method = self._BINDING_METHODS.get(binding_type)
            if binding_method is None:
                return {
                    "reason_code": LifecycleReasonCode.INSUFFICIENT_EVIDENCE,
                    "summary": "Binding type is not supported for deterministic PreparedStatement generation.",
                }
            previous_literal = output_parts[-1] if output_parts else ""
            next_literal = ""
            for candidate in parts[index + 1 :]:
                if isinstance(candidate, Literal):
                    next_literal = _decode_java_string(str(candidate.value))
                    break
            value_context = self._classify_value_context(previous_literal, next_literal)
            if value_context is None:
                return {
                    "reason_code": LifecycleReasonCode.UNSUPPORTED_REPAIR_PATTERN,
                    "summary": "SQL expression uses dynamic identifiers, clauses, or operators outside bounded value positions.",
                    "rejected_context": f"prev={previous_literal!r};next={next_literal!r}",
                }
            if value_context == "quoted" and output_parts:
                output_parts[-1] = output_parts[-1][:-1]
                strip_leading_quote = True
            output_parts.append("?")
            bindings.append(
                {
                    "index": len(bindings) + 1,
                    "expression": expression,
                    "binding_type": binding_type,
                    "binding_method": binding_method,
                }
            )
        parameterized_sql = "".join(output_parts)
        if "+" in parameterized_sql:
            return {
                "reason_code": LifecycleReasonCode.UNSUPPORTED_REPAIR_PATTERN,
                "summary": "Residual dynamic SQL fragments remain after parameterization.",
            }
        return {
            "parameterized_sql": parameterized_sql,
            "bindings": bindings,
        }

    def _classify_value_context(self, previous_literal: str, next_literal: str) -> str | None:
        prev = previous_literal.rstrip()
        nxt = next_literal.lstrip()
        if re.search(r"(?:from|join|into|update|table|order\s+by|group\s+by|select)\s*$", prev, re.IGNORECASE):
            return None
        if re.search(r"(?:where|and|or)\s*$", prev, re.IGNORECASE):
            return None
        if re.search(r"(?:=|<>|!=|<=|>=|<|>|like)\s*'$", prev, re.IGNORECASE):
            return "quoted" if nxt.startswith("'") else None
        if re.search(r"(?:=|<>|!=|<=|>=|<|>|like)\s*$", prev, re.IGNORECASE):
            return "unquoted"
        return None

    def _plan_fallback(self, *, summary: str, reason: LifecycleReasonCode) -> PluginProposal:
        return PluginProposal(
            artifact_kind=ArtifactKind.STRUCTURED_REPAIR_PLAN,
            disposition=Disposition.MANUAL_EXECUTION_REQUIRED,
            structured_repair_plan=StructuredRepairPlanArtifact(
                summary=summary,
                steps=[
                    "Replace Statement-based execution with PreparedStatement in the same method.",
                    "Convert dynamic value concatenation into placeholders with ordered bindings.",
                    "Re-run policy verification and build checks before promoting the change.",
                ],
                assumptions=["Current method-local evidence was insufficient for a deterministic patch."],
            ),
            reason_codes=[reason],
            evidence_complete=reason != LifecycleReasonCode.INSUFFICIENT_EVIDENCE,
            project_policy_dependency_resolved=True,
        )

    def _reproducibility_key(
        self,
        *,
        file_path: str,
        target_method: str,
        source: str,
        pattern_id: str,
        pattern_version: str,
        details: dict[str, Any],
    ) -> str:
        normalized = {
            "plugin_id": self.descriptor.plugin_id,
            "plugin_version": self.descriptor.plugin_version,
            "rule_id": "ISO-A.8-SQL-INJECTION",
            "pattern_id": pattern_id,
            "pattern_version": pattern_version,
            "file_path": _normalize_file_path(file_path),
            "target_method": target_method,
            "source": source,
            "details": details,
        }
        payload = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()