import unittest
from unittest.mock import patch


class _FakeResult:
    def __init__(self, records):
        self._records = records

    def __iter__(self):
        return iter(self._records)


class _FakeSession:
    def __init__(self, records):
        self._records = records

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def run(self, _cypher, _params):
        return _FakeResult(self._records)


class _FakeDriver:
    def __init__(self, records):
        self._records = records

    def session(self):
        return _FakeSession(self._records)


class TestPolicyEvaluateCaps(unittest.TestCase):
    def test_is_test_source_path_matches_src_test_only(self) -> None:
        from codegraph.policy.integration import _is_test_source_path

        self.assertTrue(_is_test_source_path("/workspace/project/src/test/java/org/example/FooTest.java"))
        self.assertTrue(_is_test_source_path(r"C:\workspace\project\src\test\java\org\example\FooTest.java"))
        self.assertFalse(_is_test_source_path("/workspace/project/src/main/java/org/example/Foo.java"))
        self.assertFalse(_is_test_source_path(None))

    def test_fetch_methods_with_context_excludes_test_sources(self) -> None:
        from codegraph.policy.integration import _fetch_methods_with_context

        records = [
            {
                "signature": "org.example.TestController.endpoint()",
                "name": "endpoint",
                "file_path": "/workspace/project/src/test/java/org/example/TestController.java",
                "start_line": 10,
                "end_line": 12,
                "modifiers": [],
                "property_annotations": ["GetMapping"],
                "class_fqn": "org.example.TestController",
                "annotation_nodes": ["GetMapping"],
                "uses_fields": [],
                "calls": [],
                "callers": [],
            },
            {
                "signature": "org.example.MainController.endpoint()",
                "name": "endpoint",
                "file_path": "/workspace/project/src/main/java/org/example/MainController.java",
                "start_line": 20,
                "end_line": 24,
                "modifiers": [],
                "property_annotations": ["GetMapping"],
                "class_fqn": "org.example.MainController",
                "annotation_nodes": ["GetMapping"],
                "uses_fields": [],
                "calls": [],
                "callers": [],
            },
        ]

        snapshots = _fetch_methods_with_context(_FakeDriver(records))

        self.assertEqual(len(snapshots), 1)
        self.assertEqual(snapshots[0]["signature"], "org.example.MainController.endpoint()")

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
            {
                "target_method": "m1",
                "file_path": "f1",
                "source_code": "public void m1() {}",
                "graph_context": {},
                "vector_context": [],
                "start_line": 10,
                "end_line": 12,
                "analysis_flags": {"md5_detected": False},
            }
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


if __name__ == "__main__":
    unittest.main()
