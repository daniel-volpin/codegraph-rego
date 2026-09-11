"""Unit tests for conditional branch reduction and collection assignment resolution."""

from __future__ import annotations

import unittest

from codegraph.policy.analysis.conditional import (
    ConditionalAssignmentResolver,
    resolve_collection_expr,
    resolve_selected_list_gets,
    resolve_selected_map_gets,
    resolve_selected_switch_body,
)


class TestConditionalResolution(unittest.TestCase):
    def test_if_else_constant_true_branch(self) -> None:
        source = 'if (10 > 5) { bar = "safe"; } else { bar = param; }'
        resolved = ConditionalAssignmentResolver.resolve(source, {})
        self.assertEqual(resolved.strip(), 'bar = "safe";')

    def test_if_else_constant_false_branch(self) -> None:
        source = 'if (10 < 5) { bar = "safe"; } else { bar = param; }'
        resolved = ConditionalAssignmentResolver.resolve(source, {})
        self.assertEqual(resolved.strip(), "bar = param;")

    def test_switch_body_matching_case(self) -> None:
        source = "switch (target) { case 'A': bar = \"safe\"; break; case 'B': bar = param; break; default: bar = \"def\"; }"
        resolved = resolve_selected_switch_body(source, {"target": "A"})
        self.assertIn('bar = "safe";', resolved)

    def test_switch_body_default_case(self) -> None:
        source = "switch (target) { case 'A': bar = \"safe\"; break; default: bar = \"def\"; }"
        resolved = resolve_selected_switch_body(source, {"target": "Z"})
        self.assertIn('bar = "def";', resolved)

    def test_list_add_and_get_resolution(self) -> None:
        source = 'list.add("item0"); list.add("item1"); bar = list.get(1);'
        resolved = resolve_selected_list_gets(source, {}, set())
        self.assertIn('bar = "item1";', resolved)

    def test_map_put_and_get_resolution(self) -> None:
        source = 'map.put("keyA", "valA"); map.put("keyB", "valB"); bar = (String) map.get("keyB");'
        resolved = resolve_selected_map_gets(source, {}, set())
        self.assertIn('bar = "valB";', resolved)

    def test_resolve_collection_expr_literal(self) -> None:
        self.assertEqual(resolve_collection_expr('"literal"', {}, set()), '"literal"')
        self.assertEqual(resolve_collection_expr("constantVar", {"constantVar": "val"}, set()), '"val"')
        self.assertEqual(resolve_collection_expr("taintedVar", {}, {"taintedVar"}), "taintedVar")
        self.assertIsNone(resolve_collection_expr("unknownVar", {}, set()))


if __name__ == "__main__":
    unittest.main()
