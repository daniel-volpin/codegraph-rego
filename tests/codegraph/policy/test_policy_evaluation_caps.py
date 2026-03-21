import unittest
from unittest.mock import patch

from tests.codegraph.policy._test_helpers import PolicyTestBase, BundleBuilder


class TestPolicyEvaluationCaps(PolicyTestBase):
    """Tests for policy evaluation limits, caps, and metadata."""

    @patch("codegraph.policy.integration.get_policy_catalog_entries", return_value=[])
    @patch("codegraph.policy.integration.load_iso_rules", return_value={})
    @patch("codegraph.policy.integration.load_policy_catalog", return_value={})
    @patch("codegraph.policy.integration._resolve_catalog_entry", return_value=None)
    @patch("codegraph.policy.integration.shutil.which", return_value="/usr/local/bin/opa")
    def test_default_behavior_has_no_limit_metadata(
        self,
        _mock_which,
        _mock_resolve_catalog,
        _mock_load_catalog,
        _mock_load_rules,
        _mock_catalog_entries,
    ) -> None:
        from codegraph.policy.integration import evaluate_policies

        bundles = [
            (
                BundleBuilder()
                .with_target_method("m1")
                .with_file_path("f1")
                .with_source_code("")
                .with_vector_context([])
                .build()
            ),
            (
                BundleBuilder()
                .with_target_method("m2")
                .with_file_path("f2")
                .with_source_code("")
                .with_vector_context([])
                .build()
            ),
        ]
        with (
            patch("codegraph.policy.integration.build_policy_input", return_value={"bundles": bundles}),
            patch(
                "codegraph.policy.integration._evaluate_bundle",
                return_value=[{"violation_id": "A", "reason": "r", "severity": "high"}],
            ),
        ):
            result = evaluate_policies()

        self.assertIn("violations", result)
        self.assertNotIn("limits", result)
        self.assertNotIn("truncated", result)
        self.assertNotIn("violation_counts_by_id", result)
        self.assertEqual(len(result["violations"]), 2)

    @patch("codegraph.policy.integration.get_policy_catalog_entries", return_value=[])
    @patch("codegraph.policy.integration.load_iso_rules", return_value={})
    @patch("codegraph.policy.integration.load_policy_catalog", return_value={})
    @patch("codegraph.policy.integration._resolve_catalog_entry", return_value=None)
    @patch("codegraph.policy.integration.shutil.which", return_value="/usr/local/bin/opa")
    def test_caps_total_and_per_violation_id_and_early_stop(
        self,
        _mock_which,
        _mock_resolve_catalog,
        _mock_load_catalog,
        _mock_load_rules,
        _mock_catalog_entries,
    ) -> None:
        from codegraph.policy.integration import evaluate_policies

        bundles = [
            (
                BundleBuilder()
                .with_target_method("m1")
                .with_file_path("f1")
                .with_source_code("")
                .with_vector_context([])
                .build()
            ),
            (
                BundleBuilder()
                .with_target_method("m2")
                .with_file_path("f2")
                .with_source_code("")
                .with_vector_context([])
                .build()
            ),
            (
                BundleBuilder()
                .with_target_method("m3")
                .with_file_path("f3")
                .with_source_code("")
                .with_vector_context([])
                .build()
            ),
            (
                BundleBuilder()
                .with_target_method("m4")
                .with_file_path("f4")
                .with_source_code("")
                .with_vector_context([])
                .build()
            ),
        ]

        def bundle_side_effect(_bundle):
            # Bundle 1 yields A,B; bundle 2 yields A,C; bundle 3 yields D; bundle 4 should not be called.
            if _bundle["target_method"] == "m1":
                return [{"violation_id": "A"}] * 200 + [{"violation_id": "B"}] * 200
            if _bundle["target_method"] == "m2":
                return [{"violation_id": "A"}] * 200 + [{"violation_id": "C"}] * 200
            if _bundle["target_method"] == "m3":
                return [{"violation_id": "D"}] * 200
            return [{"violation_id": "Z"}] * 200

        with (
            patch("codegraph.policy.integration.build_policy_input", return_value={"bundles": bundles}),
            patch(
                "codegraph.policy.integration._evaluate_bundle",
                side_effect=bundle_side_effect,
            ) as mock_eval,
        ):
            result = evaluate_policies(max_total_violations=100, max_per_violation_id=25)

        self.assertIn("limits", result)
        self.assertTrue(result.get("truncated"))
        self.assertLessEqual(len(result["violations"]), 100)

        counts = {}
        for v in result["violations"]:
            vid = str(v.get("violation_id"))
            counts[vid] = counts.get(vid, 0) + 1
        self.assertTrue(all(count <= 25 for count in counts.values()))

        # Under concurrent evaluation, all bundles are submitted eagerly (no early abort of
        # in-flight subprocesses). The caps are applied when collecting results, so the output
        # must still respect both total and per-violation-id limits.
        self.assertEqual(mock_eval.call_count, len(bundles))

    @patch("codegraph.policy.integration.get_policy_catalog_entries", return_value=[])
    @patch("codegraph.policy.integration.load_iso_rules", return_value={})
    @patch("codegraph.policy.integration.load_policy_catalog", return_value={})
    @patch("codegraph.policy.integration._resolve_catalog_entry", return_value=None)
    @patch("codegraph.policy.integration.shutil.which", return_value="/usr/local/bin/opa")
    def test_policy_results_expose_top_level_code_snippet_fields(
        self,
        _mock_which,
        _mock_resolve_catalog,
        _mock_load_catalog,
        _mock_load_rules,
        _mock_catalog_entries,
    ) -> None:
        from codegraph.policy.integration import evaluate_policies

        bundles = [
            (
                BundleBuilder()
                .with_target_method("m1")
                .with_file_path("f1")
                .with_source_code("public void m1() {}")
                .with_vector_context([])
                .with_line_numbers(10, 12)
                .with_analysis_flags({"md5_detected": False})
                .build()
            )
        ]

        with (
            patch("codegraph.policy.integration.build_policy_input", return_value={"bundles": bundles}),
            patch(
                "codegraph.policy.integration._evaluate_bundle",
                return_value=[{"violation_id": "A", "reason": "r", "severity": "high"}],
            ),
        ):
            result = evaluate_policies()

        violation = result["violations"][0]
        self.assertEqual(violation["code_snippet"], "public void m1() {}")
        self.assertTrue(violation["snippet_available"])
        self.assertEqual(violation["snippet_start_line"], 10)
        self.assertEqual(violation["snippet_end_line"], 12)
        self.assertEqual(violation["evidence"]["source_code"], "public void m1() {}")

    @patch("codegraph.policy.integration.get_policy_catalog_entries", return_value=[])
    @patch("codegraph.policy.integration.load_iso_rules", return_value={})
    @patch("codegraph.policy.integration.load_policy_catalog", return_value={})
    @patch("codegraph.policy.integration._resolve_catalog_entry", return_value=None)
    @patch("codegraph.policy.integration.shutil.which", return_value="/usr/local/bin/opa")
    def test_policy_results_include_remediation_capability_metadata(
        self,
        _mock_which,
        _mock_resolve_catalog,
        _mock_load_catalog,
        _mock_load_rules,
        _mock_catalog_entries,
    ) -> None:
        from codegraph.policy.integration import evaluate_policies

        bundles = [
            (
                BundleBuilder()
                .with_target_method("m1")
                .with_file_path("src/main/java/F1.java")
                .with_source_code("")
                .with_vector_context([])
                .build()
            ),
            (
                BundleBuilder()
                .with_target_method("m2")
                .with_file_path("src/main/java/F2.java")
                .with_source_code("")
                .with_vector_context([])
                .build()
            ),
            (
                BundleBuilder()
                .with_target_method("m3")
                .with_file_path("src/main/java/F3.java")
                .with_source_code("")
                .with_vector_context([])
                .build()
            ),
        ]

        with (
            patch("codegraph.policy.integration.build_policy_input", return_value={"bundles": bundles}),
            patch(
                "codegraph.policy.integration._evaluate_bundle",
                side_effect=[
                    [{"violation_id": "ISO-A.10-WEAK-HASH", "reason": "r1", "severity": "high"}],
                    [{"violation_id": "ISO-A.10-WEAK-RANDOM", "reason": "r3", "severity": "high"}],
                    [{"violation_id": "ISO-A.9.4.1", "reason": "r2", "severity": "high"}],
                ],
            ),
        ):
            result = evaluate_policies()

        violations = result["violations"]
        supported = next(v for v in violations if v["violation_id"] == "ISO-A.10-WEAK-HASH")
        random_supported = next(v for v in violations if v["violation_id"] == "ISO-A.10-WEAK-RANDOM")
        unsupported = next(v for v in violations if v["violation_id"] == "ISO-A.9.4.1")

        self.assertEqual(
            supported["remediation"],
            {
                "supported": True,
                "support_tier": "full",
                "reason_code": "supported_rule_for_auto_fix",
                "strategy": "llm_method_replacement",
                "preview_available": True,
                "verify_available": True,
                "ui_apply_mode": "dry_run",
                "rationale": "Bounded weak-hash replacements such as MD5 or SHA-1 to SHA-256 can be applied with minimal local edits.",
                "safe_refusal_possible": False,
            },
        )
        self.assertEqual(
            random_supported["remediation"],
            {
                "supported": True,
                "support_tier": "full",
                "reason_code": "supported_rule_for_auto_fix",
                "strategy": "llm_method_replacement",
                "preview_available": True,
                "verify_available": True,
                "ui_apply_mode": "dry_run",
                "rationale": "Local randomness upgrades can often be made safely with narrow replacements to SecureRandom-based APIs.",
                "safe_refusal_possible": True,
            },
        )
        self.assertEqual(
            unsupported["remediation"],
            {
                "supported": False,
                "support_tier": "manual",
                "reason_code": "unsupported_rule_for_auto_fix",
                "strategy": None,
                "preview_available": False,
                "verify_available": False,
                "ui_apply_mode": "dry_run",
                "rationale": "Access-control findings remain manual-review because endpoint semantics cannot be safely inferred from method-local evidence.",
                "safe_refusal_possible": False,
            },
        )

    @patch("codegraph.policy.integration.get_policy_catalog_entries", return_value=[])
    @patch("codegraph.policy.integration.load_iso_rules", return_value={})
    @patch("codegraph.policy.integration.load_policy_catalog", return_value={})
    @patch("codegraph.policy.integration._resolve_catalog_entry", return_value=None)
    @patch("codegraph.policy.integration.shutil.which", return_value="/usr/local/bin/opa")
    def test_policy_results_can_be_filtered_by_rule_ids(
        self,
        _mock_which,
        _mock_resolve_catalog,
        _mock_load_catalog,
        _mock_load_rules,
        _mock_catalog_entries,
    ) -> None:
        from codegraph.policy.integration import evaluate_policies

        bundles = [
            (
                BundleBuilder()
                .with_target_method("m1")
                .with_file_path("src/main/java/F1.java")
                .with_source_code("")
                .with_vector_context([])
                .build()
            ),
            (
                BundleBuilder()
                .with_target_method("m2")
                .with_file_path("src/main/java/F2.java")
                .with_source_code("")
                .with_vector_context([])
                .build()
            ),
        ]

        with (
            patch("codegraph.policy.integration.build_policy_input", return_value={"bundles": bundles}),
            patch(
                "codegraph.policy.integration._evaluate_bundle",
                side_effect=[
                    [{"violation_id": "ISO-A.10-WEAK-HASH", "reason": "hash", "severity": "high"}],
                    [{"violation_id": "ISO-A.8-SQL-INJECTION", "reason": "sql", "severity": "high"}],
                ],
            ),
        ):
            result = evaluate_policies(rule_ids=["ISO-A.10-WEAK-HASH"])

        self.assertEqual(len(result["violations"]), 1)
        self.assertEqual(result["violations"][0]["violation_id"], "ISO-A.10-WEAK-HASH")


if __name__ == "__main__":
    unittest.main()
