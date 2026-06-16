"""Tests for the typed Repair Intent IR (shadow-mode planning layer)."""

from __future__ import annotations

import json
import unittest
from typing import Any

from pydantic import ValidationError

from codegraph.remediation.repair_intent import (
    ConstructorReplacementOp,
    ImportAdjustmentOp,
    Invariant,
    InvariantKind,
    LiteralReplacementOp,
    MethodCallReplacementOp,
    RefusalCode,
    RefusalReason,
    RepairIntent,
    RepairIntentKind,
    SourceSpan,
    TransformationSpec,
    _preflight_refusal,
    plan_repair_intent,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_context(
    rule_id: str = "ISO-A.10-WEAK-HASH",
    target_method: str = "com.example.Foo.hash()",
    file_path: str = "src/com/example/Foo.java",
    source_code: str = 'java.security.MessageDigest.getInstance("MD5")',
    exact_method_source: str | None = None,
) -> dict[str, Any]:
    context = {
        "rule_id": rule_id,
        "target_method": target_method,
        "file_path": file_path,
        "evidence": {
            "source_code": source_code,
        },
    }
    if exact_method_source is not None:
        context["exact_method_source"] = exact_method_source
    return context


# ---------------------------------------------------------------------------
# Schema creation tests
# ---------------------------------------------------------------------------


class TestRepairIntentSchemaCreation(unittest.TestCase):
    """Validate that all model variants can be constructed correctly."""

    def test_create_literal_replacement_intent(self) -> None:
        intent = RepairIntent(
            kind=RepairIntentKind.LITERAL_REPLACEMENT,
            rule_id="ISO-A.10-WEAK-HASH",
            support_tier="full",
            target=SourceSpan(
                file_path="src/Foo.java",
                method_signature="com.example.Foo.hash()",
            ),
            transformation=TransformationSpec(
                objective="Replace MD5 with SHA-256.",
                allowed_transforms=["Replace MD5 with SHA-256"],
                non_goals=["Do not change signature"],
            ),
            invariants=[
                Invariant(
                    kind=InvariantKind.PRESERVE_METHOD_SIGNATURE,
                    description="Keep signature unchanged.",
                )
            ],
        )
        self.assertEqual(intent.kind, RepairIntentKind.LITERAL_REPLACEMENT)
        self.assertEqual(intent.support_tier, "full")
        self.assertIsNone(intent.refusal)

    def test_create_constructor_replacement_intent(self) -> None:
        intent = RepairIntent(
            kind=RepairIntentKind.CONSTRUCTOR_REPLACEMENT,
            rule_id="ISO-A.10-WEAK-RANDOM",
            support_tier="full",
            target=SourceSpan(
                file_path="src/Foo.java",
                method_signature="com.example.Foo.random()",
            ),
            transformation=TransformationSpec(
                objective="Replace Random with SecureRandom.",
            ),
        )
        self.assertEqual(intent.kind, RepairIntentKind.CONSTRUCTOR_REPLACEMENT)

    def test_create_method_call_replacement_intent(self) -> None:
        intent = RepairIntent(
            kind=RepairIntentKind.METHOD_CALL_REPLACEMENT,
            rule_id="ISO-A.10-WEAK-RANDOM",
            support_tier="full",
            target=SourceSpan(
                file_path="src/Foo.java",
                method_signature="com.example.Foo.random()",
            ),
        )
        self.assertEqual(intent.kind, RepairIntentKind.METHOD_CALL_REPLACEMENT)
        self.assertIsNone(intent.transformation)

    def test_create_import_adjustment_intent(self) -> None:
        intent = RepairIntent(
            kind=RepairIntentKind.IMPORT_ADJUSTMENT,
            rule_id="ISO-A.10-WEAK-HASH",
            support_tier="full",
            target=SourceSpan(
                file_path="src/Foo.java",
                method_signature="com.example.Foo.hash()",
            ),
        )
        self.assertEqual(intent.kind, RepairIntentKind.IMPORT_ADJUSTMENT)

    def test_create_no_repair_intent(self) -> None:
        intent = RepairIntent(
            kind=RepairIntentKind.NO_REPAIR,
            rule_id="ISO-A.8-SQL-INJECTION",
            support_tier="manual",
            target=SourceSpan(
                file_path="src/Foo.java",
                method_signature="com.example.Foo.query()",
            ),
            refusal=RefusalReason(
                code=RefusalCode.UNSUPPORTED_RULE,
                explanation="SQL injection requires cross-layer refactoring.",
            ),
        )
        self.assertEqual(intent.kind, RepairIntentKind.NO_REPAIR)
        self.assertIsNotNone(intent.refusal)
        self.assertEqual(intent.refusal.code, RefusalCode.UNSUPPORTED_RULE)

    def test_source_span_optional_lines(self) -> None:
        span = SourceSpan(
            file_path="src/Foo.java",
            method_signature="com.example.Foo.bar()",
        )
        self.assertIsNone(span.start_line)
        self.assertIsNone(span.end_line)

    def test_source_span_with_lines(self) -> None:
        span = SourceSpan(
            file_path="src/Foo.java",
            method_signature="com.example.Foo.bar()",
            start_line=10,
            end_line=25,
        )
        self.assertEqual(span.start_line, 10)
        self.assertEqual(span.end_line, 25)

    def test_all_invariant_kinds(self) -> None:
        for kind in InvariantKind:
            inv = Invariant(kind=kind, description=f"Test {kind}")
            self.assertEqual(inv.kind, kind)

    def test_all_refusal_codes(self) -> None:
        for code in RefusalCode:
            reason = RefusalReason(code=code, explanation=f"Test {code}")
            self.assertEqual(reason.code, code)

    def test_all_repair_intent_kinds(self) -> None:
        expected = {
            "literal_replacement",
            "constructor_replacement",
            "method_call_replacement",
            "import_adjustment",
            "structured_edit",
            "no_repair",
        }
        self.assertEqual(set(RepairIntentKind), expected)


# ---------------------------------------------------------------------------
# Refusal variant tests
# ---------------------------------------------------------------------------


class TestRefusalVariants(unittest.TestCase):
    """Validate refusal handling consistency."""

    def test_refusal_with_unsupported_rule(self) -> None:
        intent = RepairIntent(
            kind=RepairIntentKind.NO_REPAIR,
            rule_id="ISO-A.8-CMD-INJECTION",
            support_tier="manual",
            target=SourceSpan(file_path="x.java", method_signature="x()"),
            refusal=RefusalReason(
                code=RefusalCode.UNSUPPORTED_RULE,
                explanation="Command injection requires manual review.",
            ),
        )
        self.assertTrue(intent.kind == RepairIntentKind.NO_REPAIR)
        self.assertIsNone(intent.transformation)

    def test_refusal_with_unsupported_subcase(self) -> None:
        intent = RepairIntent(
            kind=RepairIntentKind.NO_REPAIR,
            rule_id="ISO-A.10-WEAK-CRYPTO",
            support_tier="guarded",
            target=SourceSpan(file_path="x.java", method_signature="x()"),
            refusal=RefusalReason(
                code=RefusalCode.UNSUPPORTED_SUBCASE,
                explanation="No supported cipher literal found in method.",
            ),
        )
        self.assertEqual(intent.refusal.code, RefusalCode.UNSUPPORTED_SUBCASE)
        self.assertEqual(intent.support_tier, "guarded")

    def test_refusal_with_missing_context(self) -> None:
        reason = RefusalReason(
            code=RefusalCode.MISSING_CONTEXT,
            explanation="No source code available for method.",
        )
        self.assertEqual(reason.code, RefusalCode.MISSING_CONTEXT)

    def test_refusal_with_manual_review(self) -> None:
        reason = RefusalReason(
            code=RefusalCode.MANUAL_REVIEW_REQUIRED,
            explanation="Injection families require human judgment.",
        )
        self.assertEqual(reason.code, RefusalCode.MANUAL_REVIEW_REQUIRED)


# ---------------------------------------------------------------------------
# Round-trip serialization tests
# ---------------------------------------------------------------------------


class TestRoundTripSerialization(unittest.TestCase):
    """Verify model_dump / model_validate identity for all variants."""

    def _assert_round_trip(self, intent: RepairIntent) -> None:
        dumped = intent.model_dump()
        restored = RepairIntent.model_validate(dumped)
        self.assertEqual(restored, intent)
        # Also verify JSON round-trip.
        json_str = intent.model_dump_json()
        restored_json = RepairIntent.model_validate_json(json_str)
        self.assertEqual(restored_json, intent)

    def test_round_trip_literal_replacement(self) -> None:
        self._assert_round_trip(
            RepairIntent(
                kind=RepairIntentKind.LITERAL_REPLACEMENT,
                rule_id="ISO-A.10-WEAK-HASH",
                support_tier="full",
                target=SourceSpan(
                    file_path="src/Foo.java",
                    method_signature="com.example.Foo.hash()",
                    start_line=5,
                    end_line=20,
                ),
                transformation=TransformationSpec(
                    objective="Replace MD5 with SHA-256.",
                    allowed_transforms=["Replace MD5 with SHA-256"],
                    non_goals=["Do not change signature"],
                ),
                invariants=[
                    Invariant(
                        kind=InvariantKind.PRESERVE_METHOD_SIGNATURE,
                        description="Keep signature.",
                    ),
                    Invariant(
                        kind=InvariantKind.NO_CROSS_METHOD_REFACTOR,
                        description="No cross-method refactoring.",
                    ),
                ],
            )
        )

    def test_round_trip_constructor_replacement(self) -> None:
        self._assert_round_trip(
            RepairIntent(
                kind=RepairIntentKind.CONSTRUCTOR_REPLACEMENT,
                rule_id="ISO-A.10-WEAK-RANDOM",
                support_tier="full",
                target=SourceSpan(
                    file_path="src/Foo.java",
                    method_signature="com.example.Foo.random()",
                ),
                transformation=TransformationSpec(
                    objective="Replace Random with SecureRandom.",
                ),
                invariants=[
                    Invariant(
                        kind=InvariantKind.PRESERVE_TERMINAL_INVOCATION,
                        description="Preserve terminal invocation contract.",
                    ),
                ],
            )
        )

    def test_round_trip_no_repair(self) -> None:
        self._assert_round_trip(
            RepairIntent(
                kind=RepairIntentKind.NO_REPAIR,
                rule_id="ISO-A.8-SQL-INJECTION",
                support_tier="manual",
                target=SourceSpan(
                    file_path="src/Bar.java",
                    method_signature="com.example.Bar.query()",
                ),
                refusal=RefusalReason(
                    code=RefusalCode.UNSUPPORTED_RULE,
                    explanation="Injection families are manual-review.",
                ),
            )
        )

    def test_round_trip_minimal_intent(self) -> None:
        self._assert_round_trip(
            RepairIntent(
                kind=RepairIntentKind.LITERAL_REPLACEMENT,
                rule_id="ISO-A.10-WEAK-HASH",
                support_tier="full",
                target=SourceSpan(
                    file_path="src/Foo.java",
                    method_signature="com.example.Foo.hash()",
                ),
            )
        )

    def test_round_trip_via_json_dict(self) -> None:
        intent = RepairIntent(
            kind=RepairIntentKind.CONSTRUCTOR_REPLACEMENT,
            rule_id="ISO-A.10-WEAK-RANDOM",
            support_tier="full",
            target=SourceSpan(
                file_path="src/Foo.java",
                method_signature="com.example.Foo.random()",
            ),
            transformation=TransformationSpec(
                objective="Upgrade to SecureRandom.",
            ),
        )
        json_str = json.dumps(intent.model_dump())
        restored = RepairIntent.model_validate(json.loads(json_str))
        self.assertEqual(restored, intent)


# ---------------------------------------------------------------------------
# Validation / rejection tests
# ---------------------------------------------------------------------------


class TestValidationRejection(unittest.TestCase):
    """Bad data should be rejected by Pydantic."""

    def test_missing_required_kind(self) -> None:
        with self.assertRaises(ValidationError):
            RepairIntent(
                rule_id="x",
                support_tier="full",
                target=SourceSpan(file_path="x.java", method_signature="x()"),
            )  # type: ignore[call-arg]

    def test_missing_required_rule_id(self) -> None:
        with self.assertRaises(ValidationError):
            RepairIntent(
                kind=RepairIntentKind.LITERAL_REPLACEMENT,
                support_tier="full",
                target=SourceSpan(file_path="x.java", method_signature="x()"),
            )  # type: ignore[call-arg]

    def test_missing_required_target(self) -> None:
        with self.assertRaises(ValidationError):
            RepairIntent(
                kind=RepairIntentKind.LITERAL_REPLACEMENT,
                rule_id="x",
                support_tier="full",
            )  # type: ignore[call-arg]

    def test_invalid_support_tier(self) -> None:
        with self.assertRaises(ValidationError):
            RepairIntent(
                kind=RepairIntentKind.LITERAL_REPLACEMENT,
                rule_id="x",
                support_tier="unknown",  # type: ignore[arg-type]
                target=SourceSpan(file_path="x.java", method_signature="x()"),
            )

    def test_invalid_kind_string(self) -> None:
        with self.assertRaises(ValidationError):
            RepairIntent.model_validate(
                {
                    "kind": "invalid_kind_value",
                    "rule_id": "x",
                    "support_tier": "full",
                    "target": {"file_path": "x.java", "method_signature": "x()"},
                }
            )

    def test_missing_refusal_code(self) -> None:
        with self.assertRaises(ValidationError):
            RefusalReason(
                explanation="Missing code field.",
            )  # type: ignore[call-arg]

    def test_missing_refusal_explanation(self) -> None:
        with self.assertRaises(ValidationError):
            RefusalReason(
                code=RefusalCode.UNSUPPORTED_RULE,
            )  # type: ignore[call-arg]

    def test_missing_source_span_file_path(self) -> None:
        with self.assertRaises(ValidationError):
            SourceSpan(
                method_signature="x()",
            )  # type: ignore[call-arg]

    def test_missing_invariant_description(self) -> None:
        with self.assertRaises(ValidationError):
            Invariant(
                kind=InvariantKind.PRESERVE_METHOD_SIGNATURE,
            )  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# Preflight refusal tests
# ---------------------------------------------------------------------------


class TestPreflightRefusal(unittest.TestCase):
    """Mirror the semantics of service._preflight_fixability_reason."""

    def test_weak_crypto_supported_literal(self) -> None:
        source = 'javax.crypto.Cipher.getInstance("DES/CBC/PKCS5Padding")'
        result = _preflight_refusal("ISO-A.10-WEAK-CRYPTO", source)
        self.assertIsNone(result)

    def test_weak_crypto_rc4_supported(self) -> None:
        source = 'javax.crypto.Cipher.getInstance("RC4")'
        result = _preflight_refusal("ISO-A.10-WEAK-CRYPTO", source)
        self.assertIsNone(result)

    def test_weak_crypto_aes_ecb_supported(self) -> None:
        source = 'javax.crypto.Cipher.getInstance("AES/ECB/PKCS5Padding")'
        result = _preflight_refusal("ISO-A.10-WEAK-CRYPTO", source)
        self.assertIsNone(result)

    def test_weak_crypto_no_cipher_literal(self) -> None:
        source = "some unrelated code"
        result = _preflight_refusal("ISO-A.10-WEAK-CRYPTO", source)
        self.assertIsNotNone(result)
        self.assertEqual(result.code, RefusalCode.UNSUPPORTED_SUBCASE)

    def test_weak_crypto_no_getinstance(self) -> None:
        source = '"DES/CBC/PKCS5Padding"'
        result = _preflight_refusal("ISO-A.10-WEAK-CRYPTO", source)
        self.assertIsNotNone(result)
        self.assertEqual(result.code, RefusalCode.UNSUPPORTED_SUBCASE)

    def test_weak_random_new_random(self) -> None:
        source = "float rand = new Random().nextFloat();"
        result = _preflight_refusal("ISO-A.10-WEAK-RANDOM", source)
        self.assertIsNone(result)

    def test_weak_random_math_random(self) -> None:
        source = "double r = Math.random();"
        result = _preflight_refusal("ISO-A.10-WEAK-RANDOM", source)
        self.assertIsNone(result)

    def test_weak_random_threadlocal(self) -> None:
        source = "int r = ThreadLocalRandom.current().nextInt();"
        result = _preflight_refusal("ISO-A.10-WEAK-RANDOM", source)
        self.assertIsNone(result)

    def test_weak_random_sha1prng(self) -> None:
        source = 'SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");'
        result = _preflight_refusal("ISO-A.10-WEAK-RANDOM", source)
        self.assertIsNone(result)

    def test_weak_random_unsupported_pattern(self) -> None:
        source = "some unrelated code without random usage"
        result = _preflight_refusal("ISO-A.10-WEAK-RANDOM", source)
        self.assertIsNotNone(result)
        self.assertEqual(result.code, RefusalCode.UNSUPPORTED_SUBCASE)

    def test_weak_hash_no_preflight(self) -> None:
        source = "anything"
        result = _preflight_refusal("ISO-A.10-WEAK-HASH", source)
        self.assertIsNone(result)

    def test_unrelated_rule_no_preflight(self) -> None:
        result = _preflight_refusal("ISO-A.8-SQL-INJECTION", "anything")
        self.assertIsNone(result)


# ---------------------------------------------------------------------------
# Planner output tests
# ---------------------------------------------------------------------------


class TestPlanRepairIntent(unittest.TestCase):
    """Verify planner produces correct intents for each supported family."""

    def test_weak_hash_produces_literal_replacement(self) -> None:
        ctx = _make_context(
            rule_id="ISO-A.10-WEAK-HASH",
            source_code='java.security.MessageDigest.getInstance("MD5")',
        )
        intent = plan_repair_intent(ctx)
        self.assertEqual(intent.kind, RepairIntentKind.LITERAL_REPLACEMENT)
        self.assertEqual(intent.rule_id, "ISO-A.10-WEAK-HASH")
        self.assertEqual(intent.support_tier, "full")
        self.assertIsNone(intent.refusal)
        self.assertIsNotNone(intent.transformation)
        self.assertTrue(len(intent.invariants) >= 2)

    def test_weak_random_produces_constructor_replacement(self) -> None:
        ctx = _make_context(
            rule_id="ISO-A.10-WEAK-RANDOM",
            source_code="float rand = new java.util.Random().nextFloat();",
        )
        intent = plan_repair_intent(ctx)
        self.assertEqual(intent.kind, RepairIntentKind.CONSTRUCTOR_REPLACEMENT)
        self.assertEqual(intent.rule_id, "ISO-A.10-WEAK-RANDOM")
        self.assertEqual(intent.support_tier, "full")
        self.assertIsNone(intent.refusal)
        # Constructor replacement should have a terminal-invocation invariant.
        terminal_invariants = [
            inv for inv in intent.invariants if inv.kind == InvariantKind.PRESERVE_TERMINAL_INVOCATION
        ]
        self.assertEqual(len(terminal_invariants), 1)

    def test_weak_crypto_guarded_produces_literal_replacement(self) -> None:
        ctx = _make_context(
            rule_id="ISO-A.10-WEAK-CRYPTO",
            source_code='javax.crypto.Cipher.getInstance("DES/CBC/PKCS5Padding")',
        )
        intent = plan_repair_intent(ctx)
        self.assertEqual(intent.kind, RepairIntentKind.LITERAL_REPLACEMENT)
        self.assertEqual(intent.rule_id, "ISO-A.10-WEAK-CRYPTO")
        self.assertEqual(intent.support_tier, "guarded")
        self.assertIsNone(intent.refusal)

    def test_weak_crypto_guarded_uses_exact_method_when_evidence_is_literal_stripped(self) -> None:
        ctx = _make_context(
            rule_id="ISO-A.10-WEAK-CRYPTO",
            source_code='javax.crypto.Cipher.getInstance("")',
            exact_method_source='javax.crypto.Cipher.getInstance("DES/CBC/PKCS5Padding")',
        )
        intent = plan_repair_intent(ctx)
        self.assertEqual(intent.kind, RepairIntentKind.LITERAL_REPLACEMENT)
        self.assertIsNone(intent.refusal)

    def test_weak_crypto_unsupported_subcase_produces_no_repair(self) -> None:
        ctx = _make_context(
            rule_id="ISO-A.10-WEAK-CRYPTO",
            source_code="some code without supported cipher literals",
        )
        intent = plan_repair_intent(ctx)
        self.assertEqual(intent.kind, RepairIntentKind.NO_REPAIR)
        self.assertIsNotNone(intent.refusal)
        self.assertEqual(intent.refusal.code, RefusalCode.UNSUPPORTED_SUBCASE)

    def test_weak_random_unsupported_pattern_produces_no_repair(self) -> None:
        ctx = _make_context(
            rule_id="ISO-A.10-WEAK-RANDOM",
            source_code="no random usage here",
        )
        intent = plan_repair_intent(ctx)
        self.assertEqual(intent.kind, RepairIntentKind.NO_REPAIR)
        self.assertIsNotNone(intent.refusal)
        self.assertEqual(intent.refusal.code, RefusalCode.UNSUPPORTED_SUBCASE)

    def test_unsupported_rule_produces_no_repair(self) -> None:
        ctx = _make_context(
            rule_id="ISO-A.8-SQL-INJECTION",
            source_code='String sql = "SELECT * FROM users WHERE id=" + input;',
        )
        intent = plan_repair_intent(ctx)
        self.assertEqual(intent.kind, RepairIntentKind.NO_REPAIR)
        self.assertEqual(intent.support_tier, "manual")
        self.assertIsNotNone(intent.refusal)
        self.assertEqual(intent.refusal.code, RefusalCode.UNSUPPORTED_RULE)

    def test_manual_rule_produces_no_repair(self) -> None:
        for rule_id in (
            "ISO-A.8-CMD-INJECTION",
            "ISO-A.8-PATH-TRAVERSAL",
            "ISO-A.8-LDAP-INJECTION",
            "ISO-A.8-XPATH-INJECTION",
        ):
            ctx = _make_context(rule_id=rule_id, source_code="x")
            intent = plan_repair_intent(ctx)
            self.assertEqual(intent.kind, RepairIntentKind.NO_REPAIR, f"Failed for {rule_id}")
            self.assertIsNotNone(intent.refusal, f"no refusal for {rule_id}")
            self.assertEqual(intent.refusal.code, RefusalCode.UNSUPPORTED_RULE, f"wrong code for {rule_id}")

    def test_empty_rule_id_produces_no_repair(self) -> None:
        ctx = _make_context(rule_id="", source_code="x")
        intent = plan_repair_intent(ctx)
        self.assertEqual(intent.kind, RepairIntentKind.NO_REPAIR)
        self.assertEqual(intent.refusal.code, RefusalCode.UNSUPPORTED_RULE)

    def test_planner_populates_target_from_context(self) -> None:
        ctx = _make_context(
            rule_id="ISO-A.10-WEAK-HASH",
            target_method="com.example.Foo.doHash(byte[])",
            file_path="src/com/example/Foo.java",
        )
        intent = plan_repair_intent(ctx)
        self.assertEqual(intent.target.file_path, "src/com/example/Foo.java")
        self.assertEqual(intent.target.method_signature, "com.example.Foo.doHash(byte[])")

    def test_planner_transformation_matches_fix_strategy(self) -> None:
        ctx = _make_context(rule_id="ISO-A.10-WEAK-HASH")
        intent = plan_repair_intent(ctx)
        self.assertIsNotNone(intent.transformation)
        self.assertIn("MD5", intent.transformation.objective)
        self.assertTrue(len(intent.transformation.allowed_transforms) > 0)
        self.assertTrue(len(intent.transformation.non_goals) > 0)

    def test_planner_output_is_serializable(self) -> None:
        ctx = _make_context(rule_id="ISO-A.10-WEAK-HASH")
        intent = plan_repair_intent(ctx)
        dumped = intent.model_dump()
        self.assertIsInstance(dumped, dict)
        json_str = json.dumps(dumped)
        self.assertIsInstance(json_str, str)
        restored = RepairIntent.model_validate(json.loads(json_str))
        self.assertEqual(restored, intent)

    def test_planner_no_repair_is_serializable(self) -> None:
        ctx = _make_context(rule_id="ISO-A.8-SQL-INJECTION")
        intent = plan_repair_intent(ctx)
        dumped = intent.model_dump()
        restored = RepairIntent.model_validate(dumped)
        self.assertEqual(restored, intent)
        self.assertEqual(restored.kind, RepairIntentKind.NO_REPAIR)


# ---------------------------------------------------------------------------
# Operation spec validation tests (Step 2)
# ---------------------------------------------------------------------------


class TestOperationSpecValidation(unittest.TestCase):
    """Validate creation and validation of all operation-spec types."""

    def test_literal_replacement_op(self) -> None:
        op = LiteralReplacementOp(
            target_value='"MD5"',
            replacement_value='"SHA-256"',
            qualifier_call="MessageDigest.getInstance",
        )
        self.assertEqual(op.op_type, "literal_replacement")
        self.assertEqual(op.target_value, '"MD5"')
        self.assertEqual(op.replacement_value, '"SHA-256"')

    def test_literal_replacement_op_no_qualifier(self) -> None:
        op = LiteralReplacementOp(
            target_value='"old"',
            replacement_value='"new"',
        )
        self.assertIsNone(op.qualifier_call)

    def test_constructor_replacement_op(self) -> None:
        op = ConstructorReplacementOp(
            old_type="java.util.Random",
            new_type="java.security.SecureRandom",
        )
        self.assertEqual(op.op_type, "constructor_replacement")
        self.assertTrue(op.preserve_suffix_chain)

    def test_constructor_replacement_op_no_chain(self) -> None:
        op = ConstructorReplacementOp(
            old_type="java.util.Random",
            new_type="java.security.SecureRandom",
            preserve_suffix_chain=False,
        )
        self.assertFalse(op.preserve_suffix_chain)

    def test_method_call_replacement_op(self) -> None:
        op = MethodCallReplacementOp(
            old_call_pattern="Math.random()",
            new_call_expression="new java.security.SecureRandom().nextDouble()",
        )
        self.assertEqual(op.op_type, "method_call_replacement")

    def test_import_adjustment_op(self) -> None:
        op = ImportAdjustmentOp(
            remove_import="java.util.Random",
            add_import="java.security.SecureRandom",
        )
        self.assertEqual(op.op_type, "import_adjustment")

    def test_import_adjustment_op_add_only(self) -> None:
        op = ImportAdjustmentOp(add_import="java.security.SecureRandom")
        self.assertIsNone(op.remove_import)

    def test_missing_literal_replacement_target(self) -> None:
        with self.assertRaises(ValidationError):
            LiteralReplacementOp(
                replacement_value='"SHA-256"',
            )  # type: ignore[call-arg]

    def test_missing_constructor_old_type(self) -> None:
        with self.assertRaises(ValidationError):
            ConstructorReplacementOp(
                new_type="java.security.SecureRandom",
            )  # type: ignore[call-arg]

    def test_missing_method_call_old_pattern(self) -> None:
        with self.assertRaises(ValidationError):
            MethodCallReplacementOp(
                new_call_expression="x()",
            )  # type: ignore[call-arg]

    def test_discriminated_union_via_model_validate(self) -> None:
        intent = RepairIntent.model_validate(
            {
                "kind": "literal_replacement",
                "rule_id": "ISO-A.10-WEAK-HASH",
                "support_tier": "full",
                "target": {"file_path": "x.java", "method_signature": "x()"},
                "operations": [
                    {
                        "op_type": "literal_replacement",
                        "target_value": '"MD5"',
                        "replacement_value": '"SHA-256"',
                    },
                    {
                        "op_type": "constructor_replacement",
                        "old_type": "java.util.Random",
                        "new_type": "java.security.SecureRandom",
                    },
                ],
            }
        )
        self.assertEqual(len(intent.operations), 2)
        self.assertIsInstance(intent.operations[0], LiteralReplacementOp)
        self.assertIsInstance(intent.operations[1], ConstructorReplacementOp)


# ---------------------------------------------------------------------------
# Round-trip with operations (Step 2)
# ---------------------------------------------------------------------------


class TestRoundTripWithOperations(unittest.TestCase):
    """Verify round-trip serialization of RepairIntent with operations."""

    def _assert_round_trip(self, intent: RepairIntent) -> None:
        dumped = intent.model_dump()
        restored = RepairIntent.model_validate(dumped)
        self.assertEqual(restored, intent)
        json_str = intent.model_dump_json()
        restored_json = RepairIntent.model_validate_json(json_str)
        self.assertEqual(restored_json, intent)

    def test_round_trip_with_literal_ops(self) -> None:
        self._assert_round_trip(
            RepairIntent(
                kind=RepairIntentKind.LITERAL_REPLACEMENT,
                rule_id="ISO-A.10-WEAK-HASH",
                support_tier="full",
                target=SourceSpan(file_path="x.java", method_signature="x()"),
                operations=[
                    LiteralReplacementOp(
                        target_value='"MD5"',
                        replacement_value='"SHA-256"',
                        qualifier_call="MessageDigest.getInstance",
                    ),
                ],
            )
        )

    def test_round_trip_with_constructor_ops(self) -> None:
        self._assert_round_trip(
            RepairIntent(
                kind=RepairIntentKind.CONSTRUCTOR_REPLACEMENT,
                rule_id="ISO-A.10-WEAK-RANDOM",
                support_tier="full",
                target=SourceSpan(file_path="x.java", method_signature="x()"),
                operations=[
                    ConstructorReplacementOp(
                        old_type="java.util.Random",
                        new_type="java.security.SecureRandom",
                    ),
                ],
            )
        )

    def test_round_trip_with_method_call_ops(self) -> None:
        self._assert_round_trip(
            RepairIntent(
                kind=RepairIntentKind.METHOD_CALL_REPLACEMENT,
                rule_id="ISO-A.10-WEAK-RANDOM",
                support_tier="full",
                target=SourceSpan(file_path="x.java", method_signature="x()"),
                operations=[
                    MethodCallReplacementOp(
                        old_call_pattern="Math.random()",
                        new_call_expression="new java.security.SecureRandom().nextDouble()",
                    ),
                ],
            )
        )

    def test_round_trip_with_import_ops(self) -> None:
        self._assert_round_trip(
            RepairIntent(
                kind=RepairIntentKind.IMPORT_ADJUSTMENT,
                rule_id="ISO-A.10-WEAK-RANDOM",
                support_tier="full",
                target=SourceSpan(file_path="x.java", method_signature="x()"),
                operations=[
                    ImportAdjustmentOp(
                        remove_import="java.util.Random",
                        add_import="java.security.SecureRandom",
                    ),
                ],
            )
        )

    def test_round_trip_with_mixed_ops(self) -> None:
        self._assert_round_trip(
            RepairIntent(
                kind=RepairIntentKind.LITERAL_REPLACEMENT,
                rule_id="ISO-A.10-WEAK-CRYPTO",
                support_tier="guarded",
                target=SourceSpan(file_path="x.java", method_signature="x()"),
                operations=[
                    LiteralReplacementOp(
                        target_value='"DES/CBC/PKCS5Padding"',
                        replacement_value='"AES/GCM/NoPadding"',
                        qualifier_call="Cipher.getInstance",
                    ),
                    ImportAdjustmentOp(
                        add_import="javax.crypto.spec.GCMParameterSpec",
                    ),
                ],
            )
        )

    def test_round_trip_no_ops_backward_compat(self) -> None:
        """Intents without operations (Step 1 shape) still round-trip."""
        self._assert_round_trip(
            RepairIntent(
                kind=RepairIntentKind.LITERAL_REPLACEMENT,
                rule_id="ISO-A.10-WEAK-HASH",
                support_tier="full",
                target=SourceSpan(file_path="x.java", method_signature="x()"),
            )
        )


# ---------------------------------------------------------------------------
# Planner populates operations (Step 2)
# ---------------------------------------------------------------------------


class TestPlannerPopulatesOperations(unittest.TestCase):
    """Verify plan_repair_intent populates operations for supported families."""

    def test_weak_hash_populates_literal_replacement_ops(self) -> None:
        ctx = _make_context(
            rule_id="ISO-A.10-WEAK-HASH",
            source_code='java.security.MessageDigest.getInstance("MD5")',
        )
        intent = plan_repair_intent(ctx)
        self.assertTrue(len(intent.operations) >= 1)
        op = intent.operations[0]
        self.assertIsInstance(op, LiteralReplacementOp)
        self.assertEqual(op.target_value, '"MD5"')
        self.assertEqual(op.replacement_value, '"SHA-256"')
        self.assertEqual(op.qualifier_call, "MessageDigest.getInstance")

    def test_weak_hash_sha1_populates_ops(self) -> None:
        ctx = _make_context(
            rule_id="ISO-A.10-WEAK-HASH",
            source_code='java.security.MessageDigest.getInstance("SHA-1")',
        )
        intent = plan_repair_intent(ctx)
        self.assertTrue(len(intent.operations) >= 1)
        sha1_ops = [
            op for op in intent.operations if isinstance(op, LiteralReplacementOp) and op.target_value == '"SHA-1"'
        ]
        self.assertEqual(len(sha1_ops), 1)

    def test_weak_random_new_random_populates_constructor_op(self) -> None:
        ctx = _make_context(
            rule_id="ISO-A.10-WEAK-RANDOM",
            source_code="float rand = new java.util.Random().nextFloat();",
        )
        intent = plan_repair_intent(ctx)
        ctor_ops = [op for op in intent.operations if isinstance(op, ConstructorReplacementOp)]
        self.assertEqual(len(ctor_ops), 1)
        self.assertEqual(ctor_ops[0].old_type, "java.util.Random")
        self.assertEqual(ctor_ops[0].new_type, "java.security.SecureRandom")

    def test_weak_random_math_random_populates_method_call_op(self) -> None:
        ctx = _make_context(
            rule_id="ISO-A.10-WEAK-RANDOM",
            source_code="double r = Math.random();",
        )
        intent = plan_repair_intent(ctx)
        call_ops = [op for op in intent.operations if isinstance(op, MethodCallReplacementOp)]
        self.assertEqual(len(call_ops), 1)
        self.assertEqual(call_ops[0].old_call_pattern, "Math.random()")

    def test_weak_random_threadlocal_populates_method_call_op(self) -> None:
        ctx = _make_context(
            rule_id="ISO-A.10-WEAK-RANDOM",
            source_code="int r = ThreadLocalRandom.current().nextInt();",
        )
        intent = plan_repair_intent(ctx)
        call_ops = [op for op in intent.operations if isinstance(op, MethodCallReplacementOp)]
        self.assertEqual(len(call_ops), 1)
        self.assertIn("ThreadLocalRandom", call_ops[0].old_call_pattern)

    def test_weak_random_sha1prng_populates_method_call_op(self) -> None:
        ctx = _make_context(
            rule_id="ISO-A.10-WEAK-RANDOM",
            source_code='SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");',
        )
        intent = plan_repair_intent(ctx)
        call_ops = [op for op in intent.operations if isinstance(op, MethodCallReplacementOp)]
        self.assertEqual(len(call_ops), 1)
        self.assertIn("SHA1PRNG", call_ops[0].old_call_pattern)

    def test_weak_crypto_des_populates_literal_replacement_op(self) -> None:
        ctx = _make_context(
            rule_id="ISO-A.10-WEAK-CRYPTO",
            source_code='javax.crypto.Cipher.getInstance("DES/CBC/PKCS5Padding")',
        )
        intent = plan_repair_intent(ctx)
        lit_ops = [op for op in intent.operations if isinstance(op, LiteralReplacementOp)]
        self.assertTrue(len(lit_ops) >= 1)
        self.assertIn("DES", lit_ops[0].target_value)
        self.assertIn("AES", lit_ops[0].replacement_value)

    def test_weak_crypto_rc4_populates_literal_replacement_op(self) -> None:
        ctx = _make_context(
            rule_id="ISO-A.10-WEAK-CRYPTO",
            source_code='javax.crypto.Cipher.getInstance("RC4")',
        )
        intent = plan_repair_intent(ctx)
        lit_ops = [op for op in intent.operations if isinstance(op, LiteralReplacementOp)]
        self.assertTrue(len(lit_ops) >= 1)
        rc4_ops = [op for op in lit_ops if '"RC4"' in op.target_value]
        self.assertEqual(len(rc4_ops), 1)

    def test_unsupported_rule_has_no_operations(self) -> None:
        ctx = _make_context(rule_id="ISO-A.8-SQL-INJECTION")
        intent = plan_repair_intent(ctx)
        self.assertEqual(intent.operations, [])

    def test_refusal_has_no_operations(self) -> None:
        ctx = _make_context(
            rule_id="ISO-A.10-WEAK-RANDOM",
            source_code="no random usage",
        )
        intent = plan_repair_intent(ctx)
        self.assertEqual(intent.kind, RepairIntentKind.NO_REPAIR)
        self.assertEqual(intent.operations, [])


if __name__ == "__main__":
    unittest.main()
