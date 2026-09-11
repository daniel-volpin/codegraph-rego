"""Bounded correctness regressions for deterministic patch compiler behavior."""

from __future__ import annotations

import unittest

from codegraph.remediation.patch_compiler import CompileError, compile_repair_intent
from codegraph.remediation.repair_intent import (
    ConstructorReplacementOp,
    LiteralReplacementOp,
    MethodCallReplacementOp,
    RepairIntent,
    RepairIntentKind,
    SourceSpan,
)


def _make_intent(*, operations: list, kind: RepairIntentKind = RepairIntentKind.LITERAL_REPLACEMENT) -> RepairIntent:
    return RepairIntent(
        kind=kind,
        rule_id="ISO-A.10-WEAK-HASH",
        support_tier="full",
        target=SourceSpan(file_path="x.java", method_signature="x()"),
        operations=operations,
    )


class TestBoundedCompilerPrereqs(unittest.TestCase):
    """Guard against false-positive deterministic success in shadow mode."""

    def test_conflicting_same_span_edits_raise(self) -> None:
        source = [
            "public void hash() {",
            '    MessageDigest.getInstance("MD5");',
            "}",
        ]
        intent = _make_intent(
            operations=[
                LiteralReplacementOp(
                    target_value='"MD5"',
                    replacement_value='"SHA-256"',
                    qualifier_call="MessageDigest.getInstance",
                ),
                LiteralReplacementOp(
                    target_value='"MD5"',
                    replacement_value='"SHA-512"',
                    qualifier_call="MessageDigest.getInstance",
                ),
            ]
        )
        with self.assertRaises(CompileError):
            compile_repair_intent(intent, source)

    def test_overlapping_spans_raise(self) -> None:
        source = [
            "public void random() {",
            "    double r = Math.random();",
            "}",
        ]
        intent = _make_intent(
            kind=RepairIntentKind.METHOD_CALL_REPLACEMENT,
            operations=[
                MethodCallReplacementOp(
                    old_call_pattern="Math.random()",
                    new_call_expression="new java.security.SecureRandom().nextDouble()",
                ),
                MethodCallReplacementOp(
                    old_call_pattern="Math.random()",
                    new_call_expression="secureRandom.nextDouble()",
                ),
            ],
        )
        with self.assertRaises(CompileError):
            compile_repair_intent(intent, source)

    def test_non_operational_edit_raise(self) -> None:
        source = [
            "public void hash() {",
            '    MessageDigest.getInstance("MD5");',
            "}",
        ]
        intent = _make_intent(
            operations=[
                LiteralReplacementOp(
                    target_value='"MD5"',
                    replacement_value='"MD5"',
                    qualifier_call="MessageDigest.getInstance",
                )
            ]
        )
        with self.assertRaises(CompileError):
            compile_repair_intent(intent, source)

    def test_literal_same_line_multiple_occurrences_raise(self) -> None:
        source = [
            "public void hash() {",
            '    String x = "MD5" + "MD5";',
            "}",
        ]
        intent = _make_intent(
            operations=[
                LiteralReplacementOp(
                    target_value='"MD5"',
                    replacement_value='"SHA-256"',
                )
            ]
        )
        with self.assertRaises(CompileError):
            compile_repair_intent(intent, source)

    def test_method_call_same_line_multiple_occurrences_raise(self) -> None:
        source = [
            "public void random() {",
            "    double r = Math.random() + Math.random();",
            "}",
        ]
        intent = _make_intent(
            kind=RepairIntentKind.METHOD_CALL_REPLACEMENT,
            operations=[
                MethodCallReplacementOp(
                    old_call_pattern="Math.random()",
                    new_call_expression="new java.security.SecureRandom().nextDouble()",
                )
            ],
        )
        with self.assertRaises(CompileError):
            compile_repair_intent(intent, source)

    def test_constructor_same_line_multiple_occurrences_raise(self) -> None:
        source = [
            "public void random() {",
            "    int v = new Random().nextInt() + new Random().nextInt();",
            "}",
        ]
        intent = _make_intent(
            kind=RepairIntentKind.CONSTRUCTOR_REPLACEMENT,
            operations=[
                ConstructorReplacementOp(
                    old_type="java.util.Random",
                    new_type="java.security.SecureRandom",
                )
            ],
        )
        with self.assertRaises(CompileError):
            compile_repair_intent(intent, source)

    def test_constructor_mixed_fqn_and_simple_occurrences_raise(self) -> None:
        source = [
            "public void random() {",
            "    int a = new java.util.Random().nextInt();",
            "    int b = new Random().nextInt();",
            "}",
        ]
        intent = _make_intent(
            kind=RepairIntentKind.CONSTRUCTOR_REPLACEMENT,
            operations=[
                ConstructorReplacementOp(
                    old_type="java.util.Random",
                    new_type="java.security.SecureRandom",
                )
            ],
        )
        with self.assertRaises(CompileError):
            compile_repair_intent(intent, source)


if __name__ == "__main__":
    unittest.main()
