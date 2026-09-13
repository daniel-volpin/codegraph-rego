"""Tests for the deterministic patch compiler."""

from __future__ import annotations

import unittest

from codegraph.remediation.patch_compiler import CompileError, compile_repair_intent
from codegraph.remediation.repair_intent import (
    ConstructorReplacementOp,
    ImportAdjustmentOp,
    LiteralReplacementOp,
    MethodCallReplacementOp,
    RefusalCode,
    RefusalReason,
    RepairIntent,
    RepairIntentKind,
    SourceSpan,
)


def _make_intent(
    kind: RepairIntentKind = RepairIntentKind.LITERAL_REPLACEMENT,
    operations: list | None = None,
    refusal: RefusalReason | None = None,
) -> RepairIntent:
    return RepairIntent(
        kind=kind,
        rule_id="ISO-A.10-WEAK-HASH",
        support_tier="full",
        target=SourceSpan(file_path="x.java", method_signature="x()"),
        operations=operations or [],
        refusal=refusal,
    )


# Literal replacement


class TestLiteralReplacement(unittest.TestCase):
    """Compile literal replacement operations."""

    def test_md5_to_sha256(self) -> None:
        source = [
            "public byte[] hash(byte[] data) throws Exception {",
            '    java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");',
            "    return md.digest(data);",
            "}",
        ]
        intent = _make_intent(
            operations=[
                LiteralReplacementOp(
                    target_value='"MD5"',
                    replacement_value='"SHA-256"',
                    qualifier_call="MessageDigest.getInstance",
                ),
            ]
        )
        edits = compile_repair_intent(intent, source)
        self.assertEqual(len(edits), 1)
        edit = edits[0]
        self.assertEqual(edit["start_line"], 2)
        self.assertEqual(edit["end_line"], 2)
        self.assertEqual(edit["original_lines"], [source[1]])
        self.assertEqual(len(edit["replacement_lines"]), 1)
        self.assertIn('"SHA-256"', edit["replacement_lines"][0])
        self.assertNotIn('"MD5"', edit["replacement_lines"][0].upper())

    def test_case_insensitive_match(self) -> None:
        source = [
            "public void hash() {",
            '    MessageDigest.getInstance("md5");',
            "}",
        ]
        intent = _make_intent(
            operations=[
                LiteralReplacementOp(
                    target_value='"MD5"',
                    replacement_value='"SHA-256"',
                    qualifier_call="MessageDigest.getInstance",
                ),
            ]
        )
        edits = compile_repair_intent(intent, source)
        self.assertEqual(len(edits), 1)
        self.assertIn('"SHA-256"', edits[0]["replacement_lines"][0])

    def test_qualifier_scoping(self) -> None:
        """Only match lines containing both the literal and the qualifier."""
        source = [
            "public void hash() {",
            '    String algo = "MD5";',
            '    MessageDigest md = MessageDigest.getInstance("MD5");',
            "}",
        ]
        intent = _make_intent(
            operations=[
                LiteralReplacementOp(
                    target_value='"MD5"',
                    replacement_value='"SHA-256"',
                    qualifier_call="MessageDigest.getInstance",
                ),
            ]
        )
        edits = compile_repair_intent(intent, source)
        self.assertEqual(len(edits), 1)
        self.assertEqual(edits[0]["start_line"], 3)

    def test_no_qualifier_matches_any_line(self) -> None:
        source = [
            "public void hash() {",
            '    String algo = "MD5";',
            "}",
        ]
        intent = _make_intent(
            operations=[
                LiteralReplacementOp(
                    target_value='"MD5"',
                    replacement_value='"SHA-256"',
                ),
            ]
        )
        edits = compile_repair_intent(intent, source)
        self.assertEqual(len(edits), 1)
        self.assertEqual(edits[0]["start_line"], 2)

    def test_not_found_raises(self) -> None:
        source = [
            "public void safe() {",
            '    MessageDigest.getInstance("SHA-256");',
            "}",
        ]
        intent = _make_intent(
            operations=[
                LiteralReplacementOp(
                    target_value='"MD5"',
                    replacement_value='"SHA-256"',
                    qualifier_call="MessageDigest.getInstance",
                ),
            ]
        )
        with self.assertRaises(CompileError):
            compile_repair_intent(intent, source)

    def test_ambiguous_match_raises(self) -> None:
        source = [
            "public void hash() {",
            '    MessageDigest.getInstance("MD5");',
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
            ]
        )
        with self.assertRaises(CompileError):
            compile_repair_intent(intent, source)

    def test_weak_crypto_des_replacement(self) -> None:
        source = [
            "public void encrypt() throws Exception {",
            '    Cipher c = Cipher.getInstance("DES/CBC/PKCS5Padding");',
            "}",
        ]
        intent = _make_intent(
            operations=[
                LiteralReplacementOp(
                    target_value='"DES/CBC/PKCS5Padding"',
                    replacement_value='"AES/GCM/NoPadding"',
                    qualifier_call="Cipher.getInstance",
                ),
            ]
        )
        edits = compile_repair_intent(intent, source)
        self.assertEqual(len(edits), 1)
        self.assertIn('"AES/GCM/NoPadding"', edits[0]["replacement_lines"][0])


# Constructor replacement


class TestConstructorReplacement(unittest.TestCase):
    """Compile constructor replacement operations."""

    def test_random_to_secure_random_fqn(self) -> None:
        source = [
            "public void random() {",
            "    float rand = new java.util.Random().nextFloat();",
            "}",
        ]
        intent = _make_intent(
            kind=RepairIntentKind.CONSTRUCTOR_REPLACEMENT,
            operations=[
                ConstructorReplacementOp(
                    old_type="java.util.Random",
                    new_type="java.security.SecureRandom",
                ),
            ],
        )
        edits = compile_repair_intent(intent, source)
        self.assertEqual(len(edits), 1)
        edit = edits[0]
        self.assertEqual(edit["start_line"], 2)
        self.assertIn("new java.security.SecureRandom(", edit["replacement_lines"][0])
        self.assertIn(".nextFloat()", edit["replacement_lines"][0])

    def test_random_to_secure_random_simple_name(self) -> None:
        source = [
            "public void random() {",
            "    float rand = new Random().nextFloat();",
            "}",
        ]
        intent = _make_intent(
            kind=RepairIntentKind.CONSTRUCTOR_REPLACEMENT,
            operations=[
                ConstructorReplacementOp(
                    old_type="java.util.Random",
                    new_type="java.security.SecureRandom",
                ),
            ],
        )
        edits = compile_repair_intent(intent, source)
        self.assertEqual(len(edits), 1)
        self.assertIn("new java.security.SecureRandom(", edits[0]["replacement_lines"][0])

    def test_not_found_raises(self) -> None:
        source = [
            "public void safe() {",
            "    SecureRandom sr = new SecureRandom();",
            "}",
        ]
        intent = _make_intent(
            kind=RepairIntentKind.CONSTRUCTOR_REPLACEMENT,
            operations=[
                ConstructorReplacementOp(
                    old_type="java.util.Random",
                    new_type="java.security.SecureRandom",
                ),
            ],
        )
        with self.assertRaises(CompileError):
            compile_repair_intent(intent, source)

    def test_ambiguous_match_raises(self) -> None:
        source = [
            "public void random() {",
            "    new Random().nextFloat();",
            "    new Random().nextInt();",
            "}",
        ]
        intent = _make_intent(
            kind=RepairIntentKind.CONSTRUCTOR_REPLACEMENT,
            operations=[
                ConstructorReplacementOp(
                    old_type="java.util.Random",
                    new_type="java.security.SecureRandom",
                ),
            ],
        )
        with self.assertRaises(CompileError):
            compile_repair_intent(intent, source)


# Method call replacement


class TestMethodCallReplacement(unittest.TestCase):
    """Compile method call replacement operations."""

    def test_math_random(self) -> None:
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
            ],
        )
        edits = compile_repair_intent(intent, source)
        self.assertEqual(len(edits), 1)
        self.assertIn("new java.security.SecureRandom().nextDouble()", edits[0]["replacement_lines"][0])
        self.assertNotIn("Math.random()", edits[0]["replacement_lines"][0])

    def test_threadlocal_random(self) -> None:
        source = [
            "public void random() {",
            "    int r = ThreadLocalRandom.current().nextInt();",
            "}",
        ]
        intent = _make_intent(
            kind=RepairIntentKind.METHOD_CALL_REPLACEMENT,
            operations=[
                MethodCallReplacementOp(
                    old_call_pattern="ThreadLocalRandom.current()",
                    new_call_expression="new java.security.SecureRandom()",
                ),
            ],
        )
        edits = compile_repair_intent(intent, source)
        self.assertEqual(len(edits), 1)
        self.assertIn("new java.security.SecureRandom()", edits[0]["replacement_lines"][0])

    def test_sha1prng_replacement(self) -> None:
        source = [
            "public void random() {",
            '    SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");',
            "}",
        ]
        intent = _make_intent(
            kind=RepairIntentKind.METHOD_CALL_REPLACEMENT,
            operations=[
                MethodCallReplacementOp(
                    old_call_pattern='SecureRandom.getInstance("SHA1PRNG")',
                    new_call_expression="new java.security.SecureRandom()",
                ),
            ],
        )
        edits = compile_repair_intent(intent, source)
        self.assertEqual(len(edits), 1)
        self.assertIn("new java.security.SecureRandom()", edits[0]["replacement_lines"][0])

    def test_not_found_raises(self) -> None:
        source = [
            "public void safe() {",
            "    int x = 42;",
            "}",
        ]
        intent = _make_intent(
            kind=RepairIntentKind.METHOD_CALL_REPLACEMENT,
            operations=[
                MethodCallReplacementOp(
                    old_call_pattern="Math.random()",
                    new_call_expression="x()",
                ),
            ],
        )
        with self.assertRaises(CompileError):
            compile_repair_intent(intent, source)

    def test_ambiguous_match_raises(self) -> None:
        source = [
            "public void random() {",
            "    double a = Math.random();",
            "    double b = Math.random();",
            "}",
        ]
        intent = _make_intent(
            kind=RepairIntentKind.METHOD_CALL_REPLACEMENT,
            operations=[
                MethodCallReplacementOp(
                    old_call_pattern="Math.random()",
                    new_call_expression="x()",
                ),
            ],
        )
        with self.assertRaises(CompileError):
            compile_repair_intent(intent, source)


# Import adjustment


class TestImportAdjustment(unittest.TestCase):
    """Import adjustments are explicitly unsupported in v1."""

    def test_import_adjustment_raises(self) -> None:
        source = [
            "public void hash() {",
            '    MessageDigest.getInstance("MD5");',
            "}",
        ]
        intent = _make_intent(
            operations=[
                ImportAdjustmentOp(add_import="java.security.MessageDigest"),
            ]
        )
        with self.assertRaises(CompileError):
            compile_repair_intent(intent, source)


# Edge cases


class TestCompilerEdgeCases(unittest.TestCase):
    """Edge cases and safe-failure behavior."""

    def test_no_repair_returns_empty(self) -> None:
        intent = _make_intent(
            kind=RepairIntentKind.NO_REPAIR,
            refusal=RefusalReason(
                code=RefusalCode.UNSUPPORTED_RULE,
                explanation="test",
            ),
        )
        edits = compile_repair_intent(intent, ["public void x() {}"])
        self.assertEqual(edits, [])

    def test_empty_operations_raise(self) -> None:
        intent = _make_intent(operations=[])
        with self.assertRaises(CompileError):
            compile_repair_intent(intent, ["public void x() {}"])

    def test_multi_operation_intent(self) -> None:
        source = [
            "public void crypto() throws Exception {",
            '    Cipher c = Cipher.getInstance("DES/CBC/PKCS5Padding");',
            '    SecretKey key = KeyGenerator.getInstance("DES").generateKey();',
            "}",
        ]
        intent = _make_intent(
            operations=[
                LiteralReplacementOp(
                    target_value='"DES/CBC/PKCS5Padding"',
                    replacement_value='"AES/GCM/NoPadding"',
                    qualifier_call="Cipher.getInstance",
                ),
                LiteralReplacementOp(
                    target_value='"DES"',
                    replacement_value='"AES"',
                    qualifier_call="KeyGenerator.getInstance",
                ),
            ]
        )
        edits = compile_repair_intent(intent, source)
        self.assertEqual(len(edits), 2)
        self.assertIn('"AES/GCM/NoPadding"', edits[0]["replacement_lines"][0])
        self.assertIn('"AES"', edits[1]["replacement_lines"][0])

    def test_edit_dict_shape(self) -> None:
        """Verify edit dicts have the exact shape expected by apply_method_edits."""
        source = [
            "public void hash() throws Exception {",
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
            ]
        )
        edits = compile_repair_intent(intent, source)
        edit = edits[0]
        required_keys = {"start_line", "end_line", "original_lines", "replacement_lines"}
        self.assertEqual(set(edit.keys()), required_keys)
        self.assertIsInstance(edit["start_line"], int)
        self.assertIsInstance(edit["end_line"], int)
        self.assertIsInstance(edit["original_lines"], list)
        self.assertIsInstance(edit["replacement_lines"], list)

    def test_fqn_math_random_with_package_prefix(self) -> None:
        """Method call replacement handles java.lang.Math.random()."""
        source = [
            "public void random() {",
            "    double r = java.lang.Math.random();",
            "}",
        ]
        intent = _make_intent(
            kind=RepairIntentKind.METHOD_CALL_REPLACEMENT,
            operations=[
                MethodCallReplacementOp(
                    old_call_pattern="Math.random()",
                    new_call_expression="new java.security.SecureRandom().nextDouble()",
                ),
            ],
        )
        edits = compile_repair_intent(intent, source)
        self.assertEqual(len(edits), 1)
        self.assertIn("SecureRandom", edits[0]["replacement_lines"][0])


if __name__ == "__main__":
    unittest.main()
