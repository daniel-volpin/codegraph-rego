"""Constant boolean and arithmetic expression evaluation for policy static analysis."""

from __future__ import annotations

import ast
import re

_MAX_BOOLEAN_EXPR_NODES = 64
_MAX_INTEGER_ABS = 1_000_000


def validate_numeric_value(value: int | float | bool) -> int | float | bool:
    """Ensure numeric values do not exceed safety boundaries."""
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        if abs(value) > _MAX_INTEGER_ABS:
            raise ValueError("integer_too_large")
        return value
    if isinstance(value, float):
        if abs(value) > float(_MAX_INTEGER_ABS):
            raise ValueError("float_too_large")
        return value
    raise ValueError("unsupported_numeric_value")


def eval_boolean_ast(node: ast.AST) -> int | float | bool:
    """Recursively evaluate an AST expression with bounded mathematical operations."""
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float, bool)):
        return validate_numeric_value(node.value)

    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub, ast.Not)):
        operand = eval_boolean_ast(node.operand)
        if isinstance(node.op, ast.Not):
            return not bool(operand)
        if isinstance(operand, bool):
            raise ValueError("unsupported_bool_unary")
        value = +operand if isinstance(node.op, ast.UAdd) else -operand
        return validate_numeric_value(value)

    if isinstance(node, ast.BoolOp) and isinstance(node.op, (ast.And, ast.Or)):
        values = [eval_boolean_ast(value) for value in node.values]
        if isinstance(node.op, ast.And):
            return all(bool(value) for value in values)
        return any(bool(value) for value in values)

    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Mod)):
        left = eval_boolean_ast(node.left)
        right = eval_boolean_ast(node.right)
        if isinstance(left, bool) or isinstance(right, bool):
            raise ValueError("unsupported_bool_binop")
        if isinstance(node.op, ast.Add):
            value = left + right
        elif isinstance(node.op, ast.Sub):
            value = left - right
        elif isinstance(node.op, ast.Mult):
            value = left * right
        elif isinstance(node.op, ast.Div):
            if right == 0:
                raise ValueError("division_by_zero")
            value = left / right
        else:
            if right == 0:
                raise ValueError("modulo_by_zero")
            value = left % right
        return validate_numeric_value(value)

    if isinstance(node, ast.Compare):
        left = eval_boolean_ast(node.left)
        for op, comparator in zip(node.ops, node.comparators, strict=False):
            right = eval_boolean_ast(comparator)
            if isinstance(op, ast.Eq):
                matched = left == right
            elif isinstance(op, ast.NotEq):
                matched = left != right
            elif isinstance(op, ast.Lt):
                matched = left < right
            elif isinstance(op, ast.LtE):
                matched = left <= right
            elif isinstance(op, ast.Gt):
                matched = left > right
            elif isinstance(op, ast.GtE):
                matched = left >= right
            else:
                raise ValueError("unsupported_compare")
            if not matched:
                return False
            left = right
        return True

    raise ValueError("unsupported_expression")


def evaluate_constant_boolean(expr: str, int_constants: dict[str, int]) -> bool | None:
    """Evaluate whether an expression simplifies to a constant boolean value under known integer constants."""
    normalized = expr
    for var, value in int_constants.items():
        normalized = re.sub(rf"\b{re.escape(var)}\b", str(value), normalized)
    normalized = normalized.replace("&&", " and ").replace("||", " or ")
    if re.search(r"\b(?!and\b|or\b)[A-Za-z_][A-Za-z0-9_]*\b", normalized):
        return None
    if not re.fullmatch(r"[0-9\s()+\-*/%<>=!&|.andor]+", normalized):
        return None
    try:
        parsed = ast.parse(normalized, mode="eval")
        if sum(1 for _ in ast.walk(parsed)) > _MAX_BOOLEAN_EXPR_NODES:
            return None
        value = eval_boolean_ast(parsed.body)
    except Exception:
        return None
    return bool(value) if isinstance(value, (bool, int, float)) else None
