import unittest
from unittest.mock import patch


class TestPolicyEvaluateCaps(unittest.TestCase):
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
            {"target_method": "m1", "file_path": "f1", "source_code": "", "graph_context": {}, "vector_context": []},
            {"target_method": "m2", "file_path": "f2", "source_code": "", "graph_context": {}, "vector_context": []},
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
            {"target_method": "m1", "file_path": "f1", "source_code": "", "graph_context": {}, "vector_context": []},
            {"target_method": "m2", "file_path": "f2", "source_code": "", "graph_context": {}, "vector_context": []},
            {"target_method": "m3", "file_path": "f3", "source_code": "", "graph_context": {}, "vector_context": []},
            {"target_method": "m4", "file_path": "f4", "source_code": "", "graph_context": {}, "vector_context": []},
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

        # Early stop: we should not need to evaluate all 4 bundles to reach 100 under these caps.
        self.assertLess(mock_eval.call_count, len(bundles))


if __name__ == "__main__":
    unittest.main()
