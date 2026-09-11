"""Unit tests for AST constant boolean and arithmetic expression evaluation."""

from __future__ import annotations

import unittest

from codegraph.policy.analysis.boolean_eval import (
    evaluate_constant_boolean,
    validate_numeric_value,
)


class TestBooleanEvaluation(unittest.TestCase):
    def test_simple_arithmetic_comparison(self) -> None:
        self.assertTrue(evaluate_constant_boolean("500 / 42 > 10", {}))
        self.assertFalse(evaluate_constant_boolean("500 / 42 < 10", {}))

    def test_variable_substitution(self) -> None:
        constants = {"num": 196}
        self.assertTrue(evaluate_constant_boolean("(500 / 42) + num > 200", constants))
        self.assertFalse(evaluate_constant_boolean("(500 / 42) + num > 300", constants))

    def test_boolean_logical_operators(self) -> None:
        constants = {"a": 10, "b": 20}
        self.assertTrue(evaluate_constant_boolean("a < 15 && b > 15", constants))
        self.assertTrue(evaluate_constant_boolean("a > 15 || b > 15", constants))
        self.assertFalse(evaluate_constant_boolean("a > 15 && b > 15", constants))

    def test_unresolved_variable_returns_none(self) -> None:
        self.assertIsNone(evaluate_constant_boolean("unknownVar > 10", {}))

    def test_division_by_zero_returns_none(self) -> None:
        self.assertIsNone(evaluate_constant_boolean("100 / 0 > 1", {}))

    def test_modulo_by_zero_returns_none(self) -> None:
        self.assertIsNone(evaluate_constant_boolean("100 % 0 == 0", {}))

    def test_numeric_boundary_enforcement(self) -> None:
        self.assertEqual(validate_numeric_value(100), 100)
        self.assertEqual(validate_numeric_value(100.5), 100.5)
        self.assertTrue(validate_numeric_value(True))
        with self.assertRaises(ValueError):
            validate_numeric_value(10_000_000)


if __name__ == "__main__":
    unittest.main()
