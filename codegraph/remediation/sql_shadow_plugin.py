from __future__ import annotations

# pyright: reportMissingImports=false, reportMissingTypeStubs=false
import hashlib
import json
import re
from difflib import SequenceMatcher
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
    NearMissKind,
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


def _java_string_literal(value: str) -> str:
    escaped = json.dumps(value, ensure_ascii=True)
    return escaped


def _type_name(type_node: Any) -> str:
    name = str(getattr(type_node, "name", type_node))
    sub_type = getattr(type_node, "sub_type", None)
    while sub_type is not None:
        name = f"{name}.{getattr(sub_type, 'name', sub_type)}"
        sub_type = getattr(sub_type, "sub_type", None)
    return name


def _block_for_statement(method_lines: list[str], start_line: int) -> tuple[int, list[str]]:
    end_line = start_line
    collected: list[str] = []
    for idx in range(start_line - 1, len(method_lines)):
        collected.append(method_lines[idx])
        end_line = idx + 1
        if ";" in method_lines[idx]:
            break
    return end_line, collected


def _line_indent(line: str) -> str:
    match = re.match(r"\s*", line)
    return match.group(0) if match else ""


def _statement_text(lines: list[str]) -> str:
    return "\n".join(lines)


def _replace_execute_invocation_text(statement_text: str, statement_var: str, execute_method: str) -> str:
    pattern = re.compile(
        rf"(?P<prefix>\breturn\s+)?{re.escape(statement_var)}\s*\.\s*(?P<member>{execute_method})\s*\((?P<args>.*?)\)",
        re.DOTALL,
    )
    match = pattern.search(statement_text)
    if match is None:
        return statement_text
    prefix = match.group("prefix") or ""
    replacement = f"{prefix}{statement_var}.{match.group('member')}()"
    return f"{statement_text[:match.start()]}{replacement}{statement_text[match.end():]}"


def _binding_index_value(node: Any) -> int | None:
    literal_value = getattr(node, "value", None)
    if literal_value is None:
        return None
    try:
        return int(str(literal_value))
    except ValueError:
        return None


def _binding_expression_text(node: Any) -> str | None:
    if isinstance(node, MemberReference):
        if node.qualifier:
            return f"{node.qualifier}.{node.member}"
        return str(node.member)
    return None


def _count_sql_placeholders(sql_literal: str) -> tuple[int, list[tuple[int, NearMissKind | None]]]:
    count = 0
    positions: list[tuple[int, NearMissKind | None]] = []
    in_single_quote = False
    idx = 0
    while idx < len(sql_literal):
        char = sql_literal[idx]
        if char == "'":
            if in_single_quote and idx + 1 < len(sql_literal) and sql_literal[idx + 1] == "'":
                idx += 2
                continue
            in_single_quote = not in_single_quote
        elif char == "?" and not in_single_quote:
            count += 1
            positions.append((idx, None))
        idx += 1
    return count, positions


def _actual_edit_scope(original_source: str, updated_source: str) -> dict[str, Any]:
    original_lines = original_source.splitlines()
    updated_lines = updated_source.splitlines()
    matcher = SequenceMatcher(a=original_lines, b=updated_lines)
    changed_lines: list[int] = []
    for tag, _i1, _i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        changed_lines.extend(range(j1 + 1, j2 + 1))
    if not changed_lines:
        return {"changed_line_count": 0, "changed_lines": [], "changed_span": 0}
    return {
        "changed_line_count": len(changed_lines),
        "changed_lines": changed_lines,
        "changed_span": changed_lines[-1] - changed_lines[0] + 1,
    }


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
                    "sql.prepared_statement_declared",
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
                auto_apply_capable=False,
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
                    "sql.prepared_statement_declared",
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
                auto_apply_capable=False,
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
                context=context,
                summary="Exact method source is required for bounded SQL repair.",
                reason=LifecycleReasonCode.INSUFFICIENT_EVIDENCE,
            )

        method, line_offset = self._parse_method(source)
        if method is None:
            return self._plan_fallback(
                context=context,
                summary="Method snippet could not be parsed for deterministic SQL transformation.",
                reason=LifecycleReasonCode.INSUFFICIENT_EVIDENCE,
            )

        symbol_types = self._collect_symbol_types(method)
        match = self._find_sql_candidate(method, source.splitlines(), symbol_types, line_offset)
        if match is None:
            return self._plan_fallback(
                context=context,
                summary="SQL query shape is outside the bounded JDBC parameterization patterns.",
                reason=LifecycleReasonCode.UNSUPPORTED_REPAIR_PATTERN,
            )
        if match.get("reason_code") is not None:
            reason_code = match["reason_code"]
            summary = str(match.get("summary") or "SQL remediation candidate was rejected.")
            return self._plan_fallback(
                context=context,
                summary=summary,
                reason=reason_code,
                near_miss_classification=match.get("near_miss_classification"),
            )

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
        method_source = updated_method_source or ""
        if not method_source.strip():
            return [
                ValidatorResult(
                    validator_id="sql.prepared_statement_declared",
                    state=ValidatorState.ERROR,
                    required=True,
                    message="Updated method source is required for semantic validation.",
                )
            ]

        evidence = self._semantic_evidence_from_method_source(method_source)
        original_source = str(context.get("exact_method_source") or "")
        scope = _actual_edit_scope(original_source, method_source)

        if evidence.get("parse_error"):
            validators = [
                ValidatorResult(
                    validator_id="sql.prepared_statement_declared",
                    state=ValidatorState.FAIL,
                    required=True,
                    message=str(evidence["parse_error"]),
                ),
                ValidatorResult(
                    validator_id="sql.edit_scope",
                    state=ValidatorState.FAIL if scope["changed_line_count"] == 0 else ValidatorState.PASS,
                    required=True,
                    details=scope,
                ),
            ]
            validators.append(
                ValidatorResult(
                    validator_id="sql.proposal_consistency",
                    state=ValidatorState.NOT_APPLICABLE,
                    required=False,
                )
            )
            return validators

        derived_bindings = list(evidence.get("bindings") or [])
        derived_binding_indexes = [binding["index"] for binding in derived_bindings]
        placeholder_count = int(evidence.get("placeholder_count") or 0)
        unresolved_symbols = list(evidence.get("unresolved_symbols") or [])
        invalid_placeholder_contexts = list(evidence.get("invalid_placeholder_contexts") or [])
        max_edit_scope_lines = proposal.patch_pattern.max_edit_scope_lines
        validators = [
            ValidatorResult(
                validator_id="sql.prepared_statement_declared",
                state=ValidatorState.PASS if evidence.get("prepared_statement_var") else ValidatorState.FAIL,
                required=True,
                details={
                    "prepared_statement_var": evidence.get("prepared_statement_var"),
                    "sql_variable": evidence.get("sql_variable"),
                },
            ),
            ValidatorResult(
                validator_id="sql.constant_structure",
                state=ValidatorState.PASS if evidence.get("sql_literal") and not evidence.get("dynamic_sql_source") else ValidatorState.FAIL,
                required=True,
                details={"sql_literal": evidence.get("sql_literal")},
            ),
            ValidatorResult(
                validator_id="sql.placeholder_count",
                state=ValidatorState.PASS if placeholder_count == len(derived_bindings) else ValidatorState.FAIL,
                required=True,
                details={"placeholders": placeholder_count, "bindings": len(derived_bindings)},
            ),
            ValidatorResult(
                validator_id="sql.binding_order",
                state=(
                    ValidatorState.PASS
                    if derived_binding_indexes == list(range(1, len(derived_bindings) + 1))
                    else ValidatorState.FAIL
                ),
                required=True,
                details={"binding_indexes": derived_binding_indexes},
            ),
            ValidatorResult(
                validator_id="sql.binding_types",
                state=(
                    ValidatorState.PASS
                    if derived_bindings and all(binding["binding_method"] in self._BINDING_METHODS.values() for binding in derived_bindings)
                    else ValidatorState.FAIL
                ),
                required=True,
                details={"bindings": derived_bindings},
            ),
            ValidatorResult(
                validator_id="sql.executed_prepared_statement",
                state=(
                    ValidatorState.PASS
                    if evidence.get("executed_statement_var") == evidence.get("prepared_statement_var")
                    and evidence.get("executed_method") in {"executeQuery", "executeUpdate"}
                    else ValidatorState.FAIL
                ),
                required=True,
                details={
                    "executed_statement_var": evidence.get("executed_statement_var"),
                    "executed_method": evidence.get("executed_method"),
                },
            ),
            ValidatorResult(
                validator_id="sql.dynamic_sink_removed",
                state=(
                    ValidatorState.PASS
                    if not evidence.get("statement_declarations") and not evidence.get("dynamic_execute_calls")
                    else ValidatorState.FAIL
                ),
                required=True,
                details={
                    "statement_declarations": evidence.get("statement_declarations"),
                    "dynamic_execute_calls": evidence.get("dynamic_execute_calls"),
                },
            ),
            ValidatorResult(
                validator_id="sql.no_forbidden_dynamic_clause",
                state=ValidatorState.PASS if not invalid_placeholder_contexts and not evidence.get("dynamic_sql_source") else ValidatorState.FAIL,
                required=True,
                details={
                    "invalid_placeholder_contexts": invalid_placeholder_contexts,
                    "dynamic_sql_source": evidence.get("dynamic_sql_source"),
                },
            ),
            ValidatorResult(
                validator_id="sql.edit_scope",
                state=(
                    ValidatorState.PASS
                    if 0 < scope["changed_line_count"] <= max_edit_scope_lines
                    else ValidatorState.FAIL
                ),
                required=True,
                details=scope,
            ),
            ValidatorResult(
                validator_id="sql.no_invented_symbols",
                state=ValidatorState.PASS if not unresolved_symbols else ValidatorState.FAIL,
                required=True,
                details={"unresolved_symbols": unresolved_symbols},
            ),
        ]

        proposal_bindings = list(proposal.details.get("bindings") or [])
        validators.append(
            ValidatorResult(
                validator_id="sql.proposal_consistency",
                state=(
                    ValidatorState.PASS
                    if proposal.details.get("parameterized_sql") == evidence.get("sql_literal")
                    and proposal_bindings == derived_bindings
                    else ValidatorState.FAIL
                ),
                required=False,
                details={
                    "proposal_sql": proposal.details.get("parameterized_sql"),
                    "derived_sql": evidence.get("sql_literal"),
                },
            )
        )
        return validators

    def _semantic_evidence_from_method_source(self, method_source: str) -> dict[str, Any]:
        method, line_offset = self._parse_method(method_source)
        if method is None:
            return {"parse_error": "Patched method source could not be parsed for semantic validation."}

        declared_symbols = self._collect_declared_symbols(method)
        string_literals = self._collect_string_literals(method)
        prepared_statement = self._find_prepared_statement(method, string_literals, line_offset)
        if prepared_statement is None:
            return {
                "prepared_statement_var": None,
                "statement_declarations": self._find_statement_declarations(method),
                "dynamic_execute_calls": self._find_dynamic_execute_calls(method),
                "unresolved_symbols": [],
                "dynamic_sql_source": True,
                "invalid_placeholder_contexts": [],
                "bindings": [],
                "placeholder_count": 0,
            }

        bindings, unresolved_symbols = self._find_bindings(method, prepared_statement["statement_var"], declared_symbols)
        executed_statement_var, executed_method = self._find_executed_statement(method)
        placeholder_count, invalid_placeholder_contexts = self._validate_sql_literal(prepared_statement["sql_literal"])
        unresolved_symbols.extend(symbol for symbol in prepared_statement["unresolved_symbols"] if symbol not in unresolved_symbols)
        return {
            "prepared_statement_var": prepared_statement["statement_var"],
            "sql_variable": prepared_statement["sql_variable"],
            "sql_literal": prepared_statement["sql_literal"],
            "statement_declarations": self._find_statement_declarations(method),
            "dynamic_execute_calls": self._find_dynamic_execute_calls(method),
            "dynamic_sql_source": prepared_statement["dynamic_sql_source"],
            "bindings": bindings,
            "placeholder_count": placeholder_count,
            "invalid_placeholder_contexts": invalid_placeholder_contexts,
            "executed_statement_var": executed_statement_var,
            "executed_method": executed_method,
            "unresolved_symbols": unresolved_symbols,
        }

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
                symbol_types[str(parameter.name)] = _type_name(parameter.type)
        for _, node in method:
            if isinstance(node, LocalVariableDeclaration):
                type_name = _type_name(node.type)
                for declarator in node.declarators:
                    symbol_types[str(declarator.name)] = type_name
        return symbol_types

    def _collect_declared_symbols(self, method: MethodDeclaration) -> set[str]:
        declared_symbols = {str(parameter.name) for parameter in getattr(method, "parameters", []) or [] if getattr(parameter, "name", None)}
        for _, node in method:
            if isinstance(node, LocalVariableDeclaration):
                for declarator in node.declarators:
                    declared_symbols.add(str(declarator.name))
        return declared_symbols

    def _collect_string_literals(self, method: MethodDeclaration) -> dict[str, str]:
        string_literals: dict[str, str] = {}
        for _, node in method:
            if not isinstance(node, LocalVariableDeclaration):
                continue
            if _type_name(node.type) not in {"String", "java.lang.String"}:
                continue
            for declarator in node.declarators:
                initializer = declarator.initializer
                if isinstance(initializer, Literal):
                    string_literals[str(declarator.name)] = _decode_java_string(str(initializer.value))
        return string_literals

    def _find_prepared_statement(
        self,
        method: MethodDeclaration,
        string_literals: dict[str, str],
        line_offset: int,
    ) -> dict[str, Any] | None:
        for _, node in method:
            if not isinstance(node, LocalVariableDeclaration):
                continue
            if not _type_name(node.type).endswith("PreparedStatement"):
                continue
            for declarator in node.declarators:
                initializer = declarator.initializer
                if not isinstance(initializer, MethodInvocation) or initializer.member != "prepareStatement":
                    continue
                if len(initializer.arguments or []) != 1:
                    continue
                sql_argument = initializer.arguments[0]
                unresolved_symbols: list[str] = []
                sql_literal: str | None = None
                sql_variable: str | None = None
                dynamic_sql_source = False
                if isinstance(sql_argument, Literal):
                    sql_literal = _decode_java_string(str(sql_argument.value))
                elif isinstance(sql_argument, MemberReference):
                    sql_variable = _member_ref_text(sql_argument)
                    if sql_variable is None or sql_variable not in string_literals:
                        dynamic_sql_source = True
                        if sql_variable is not None:
                            unresolved_symbols.append(sql_variable)
                    else:
                        sql_literal = string_literals[sql_variable]
                else:
                    dynamic_sql_source = True
                return {
                    "statement_var": str(declarator.name),
                    "sql_variable": sql_variable,
                    "sql_literal": sql_literal,
                    "dynamic_sql_source": dynamic_sql_source or sql_literal is None,
                    "unresolved_symbols": unresolved_symbols,
                    "line": (node.position.line - line_offset) if node.position else None,
                }
        return None

    def _find_statement_declarations(self, method: MethodDeclaration) -> list[str]:
        declarations: list[str] = []
        for _, node in method:
            if not isinstance(node, LocalVariableDeclaration):
                continue
            if _type_name(node.type).endswith("Statement") and not _type_name(node.type).endswith("PreparedStatement"):
                for declarator in node.declarators:
                    declarations.append(str(declarator.name))
        return declarations

    def _find_dynamic_execute_calls(self, method: MethodDeclaration) -> list[str]:
        calls: list[str] = []
        for _, node in method:
            if isinstance(node, MethodInvocation) and node.member in {"executeQuery", "executeUpdate"} and len(node.arguments or []) > 0:
                calls.append(str(node.qualifier or "unknown"))
        return calls

    def _find_bindings(
        self,
        method: MethodDeclaration,
        statement_var: str,
        declared_symbols: set[str],
    ) -> tuple[list[dict[str, Any]], list[str]]:
        bindings: list[dict[str, Any]] = []
        unresolved_symbols: list[str] = []
        for _, node in method:
            if not isinstance(node, MethodInvocation) or node.qualifier != statement_var:
                continue
            if not node.member.startswith("set") or len(node.arguments or []) != 2:
                continue
            index = _binding_index_value(node.arguments[0])
            expression = _binding_expression_text(node.arguments[1])
            if expression is None:
                unresolved_symbols.append(f"unsupported:{node.member}")
                continue
            if "." in expression:
                unresolved_symbols.append(expression)
            elif expression not in declared_symbols:
                unresolved_symbols.append(expression)
            bindings.append(
                {
                    "index": index,
                    "expression": expression,
                    "binding_method": str(node.member),
                }
            )
        bindings.sort(key=lambda binding: (binding["index"] is None, binding["index"] or 0, binding["expression"]))
        return bindings, unresolved_symbols

    def _find_executed_statement(self, method: MethodDeclaration) -> tuple[str | None, str | None]:
        executed_calls: list[tuple[int, str | None, str]] = []
        for _, node in method:
            if not isinstance(node, MethodInvocation) or node.member not in {"executeQuery", "executeUpdate"}:
                continue
            if len(node.arguments or []) != 0:
                continue
            line = node.position.line if node.position is not None else 0
            executed_calls.append((line, str(node.qualifier) if node.qualifier else None, str(node.member)))
        if not executed_calls:
            return None, None
        executed_calls.sort(key=lambda item: item[0])
        _line, qualifier, member = executed_calls[-1]
        return qualifier, member

    def _validate_sql_literal(self, sql_literal: str | None) -> tuple[int, list[dict[str, Any]]]:
        if sql_literal is None:
            return 0, [{"classification": NearMissKind.RESIDUAL_DYNAMIC_SQL.value, "position": None}]
        placeholder_count, placeholders = _count_sql_placeholders(sql_literal)
        invalid_contexts: list[dict[str, Any]] = []
        for position, _ in placeholders:
            value_context, near_miss = self._classify_value_context(sql_literal[:position], sql_literal[position + 1 :])
            if value_context is None:
                invalid_contexts.append(
                    {
                        "classification": (near_miss or NearMissKind.RESIDUAL_DYNAMIC_SQL).value,
                        "position": position,
                    }
                )
        return placeholder_count, invalid_contexts

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
            statement_end_line, statement_original_lines = _block_for_statement(method_lines, statement_line)
            execute_end_line, execute_original_lines = _block_for_statement(method_lines, execute_line)
            edits: list[dict[str, Any]] = []

            if query_line is not None:
                query_end_line, query_original_lines = _block_for_statement(method_lines, query_line)
                query_replacement_lines = [
                    f"{_line_indent(query_original_lines[0])}String {query_var_name} = {_java_string_literal(parameterized_sql)};"
                ]
                if query_replacement_lines == query_original_lines:
                    return {
                        "reason_code": LifecycleReasonCode.TRANSFORMATION_FAILURE,
                        "summary": "Query literal replacement produced no source change.",
                    }
                edits.append(
                    {
                        "start_line": query_line,
                        "end_line": query_end_line,
                        "original_lines": query_original_lines,
                        "replacement_lines": query_replacement_lines,
                    }
                )
                statement_replacement_lines = [
                    f"{_line_indent(statement_original_lines[0])}java.sql.PreparedStatement {statement_var} = {connection_expr}.prepareStatement({query_var_name});"
                ]
            else:
                statement_replacement_lines = [
                    f"{_line_indent(statement_original_lines[0])}java.sql.PreparedStatement {statement_var} = {connection_expr}.prepareStatement({_java_string_literal(parameterized_sql)});"
                ]
            if statement_replacement_lines == statement_original_lines:
                return {
                    "reason_code": LifecycleReasonCode.TRANSFORMATION_FAILURE,
                    "summary": "PreparedStatement declaration replacement produced no source change.",
                }
            edits.append(
                {
                    "start_line": statement_line,
                    "end_line": statement_end_line,
                    "original_lines": statement_original_lines,
                    "replacement_lines": statement_replacement_lines,
                }
            )

            binding_lines = [
                f'{statement_var}.{binding["binding_method"]}({binding["index"]}, {binding["expression"]});'
                for binding in bindings
            ]
            execute_indent = _line_indent(execute_original_lines[0])
            indented_binding_lines = [f"{execute_indent}{line}" for line in binding_lines]
            execute_replacement = _replace_execute_invocation_text(
                _statement_text(execute_original_lines),
                statement_var,
                execute_method,
            )
            execute_replacement_lines = execute_replacement.splitlines()
            if execute_replacement_lines == execute_original_lines:
                return {
                    "reason_code": LifecycleReasonCode.TRANSFORMATION_FAILURE,
                    "summary": "Statement execution replacement produced no source change.",
                }
            edits.append(
                {
                    "start_line": execute_line,
                    "end_line": execute_end_line,
                    "original_lines": execute_original_lines,
                    "replacement_lines": [*indented_binding_lines, *execute_replacement_lines],
                }
            )
            return {
                "pattern_id": "SQL-VAL-001" if query_line is not None else "SQL-VAL-002",
                "edits": edits,
                "bindings": bindings,
                "placeholder_count": self._validate_sql_literal(parameterized_sql)[0],
                "parameterized_sql": parameterized_sql,
                "statement_var": statement_var,
                "connection_expr": connection_expr,
                "near_miss_classification": None,
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
            value_context, near_miss = self._classify_value_context(previous_literal, next_literal)
            if value_context is None:
                return {
                    "reason_code": LifecycleReasonCode.UNSUPPORTED_REPAIR_PATTERN,
                    "summary": "SQL expression uses dynamic identifiers, clauses, or operators outside bounded value positions.",
                    "near_miss_classification": near_miss,
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
                "near_miss_classification": NearMissKind.RESIDUAL_DYNAMIC_SQL,
            }
        return {
            "parameterized_sql": parameterized_sql,
            "bindings": bindings,
        }

    def _classify_value_context(self, previous_literal: str, next_literal: str) -> tuple[str | None, NearMissKind | None]:
        prev = previous_literal.rstrip()
        nxt = next_literal.lstrip()
        if re.search(r"(?:order\s+by|group\s+by)\s*$", prev, re.IGNORECASE):
            return None, NearMissKind.DYNAMIC_ORDER_BY
        if re.search(r"(?:from|join|into|update|table|select)\s*$", prev, re.IGNORECASE):
            return None, NearMissKind.DYNAMIC_IDENTIFIER
        if re.search(r"(?:where|and|or)\s*$", prev, re.IGNORECASE):
            return None, NearMissKind.DYNAMIC_CLAUSE
        if re.search(r"(?:=|<>|!=|<=|>=|<|>|like)\s*'$", prev, re.IGNORECASE):
            return ("quoted", None) if nxt.startswith("'") else (None, NearMissKind.DYNAMIC_OPERATOR)
        if re.search(r"(?:=|<>|!=|<=|>=|<|>|like)\s*$", prev, re.IGNORECASE):
            return "unquoted", None
        return None, NearMissKind.DYNAMIC_OPERATOR

    def _plan_fallback(
        self,
        *,
        context: dict[str, Any],
        summary: str,
        reason: LifecycleReasonCode,
        near_miss_classification: NearMissKind | None = None,
    ) -> PluginProposal:
        structured_repair_plan = StructuredRepairPlanArtifact(
            summary=summary,
            steps=[
                "Replace Statement-based execution with PreparedStatement in the same method.",
                "Convert dynamic value concatenation into placeholders with ordered bindings.",
                "Re-run policy verification and build checks before promoting the change.",
            ],
            assumptions=["Current method-local evidence was insufficient for a deterministic patch."],
        )
        payload = {
            "artifact_kind": ArtifactKind.STRUCTURED_REPAIR_PLAN.value,
            "disposition": Disposition.MANUAL_EXECUTION_REQUIRED.value,
            "reason_codes": [reason.value],
            "near_miss_classification": near_miss_classification.value if near_miss_classification else None,
            "structured_repair_plan": structured_repair_plan.model_dump(mode="json"),
        }
        return PluginProposal(
            artifact_kind=ArtifactKind.STRUCTURED_REPAIR_PLAN,
            disposition=Disposition.MANUAL_EXECUTION_REQUIRED,
            structured_repair_plan=structured_repair_plan,
            reason_codes=[reason],
            evidence_complete=reason != LifecycleReasonCode.INSUFFICIENT_EVIDENCE,
            project_policy_dependency_resolved=True,
            details={
                "near_miss_classification": near_miss_classification.value if near_miss_classification else None,
                "reproducibility_key": self._reproducibility_key(
                    file_path=str(context.get("file_path") or "unknown"),
                    target_method=str(context.get("target_method") or "unknown"),
                    source=str(context.get("exact_method_source") or ""),
                    pattern_id="abstain",
                    pattern_version="1.0.0",
                    details=payload,
                ),
            },
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