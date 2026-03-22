"""Tests for evidence provenance summary in build_violation_response."""
from __future__ import annotations

import unittest


def _build(bundle: dict, normalized: dict | None = None) -> dict:
    from codegraph.policy.runtime.opa import build_violation_response

    if normalized is None:
        normalized = {"violation_id": "ISO-A.10-WEAK-HASH", "reason": "MD5 used"}
    return build_violation_response(normalized, bundle, control_meta=None)


class TestEvidenceProvenanceField(unittest.TestCase):
    """build_violation_response must include evidence.provenance on every call."""

    def _provenance(self, bundle: dict) -> dict:
        return _build(bundle)["evidence"]["provenance"]

    # ------------------------------------------------------------------
    # Structure
    # ------------------------------------------------------------------

    def test_provenance_key_exists(self) -> None:
        result = _build({})
        self.assertIn("provenance", result["evidence"])

    def test_provenance_has_all_expected_keys(self) -> None:
        prov = self._provenance({})
        expected = {
            "graph_context_populated",
            "source_snippet_resolved",
            "analysis_flags_active",
            "vector_context_available",
            "taint_paths_available",
        }
        self.assertEqual(set(prov.keys()), expected)

    # ------------------------------------------------------------------
    # graph_context_populated
    # ------------------------------------------------------------------

    def test_graph_context_populated_false_when_empty(self) -> None:
        bundle = {"graph_context": {"calls": [], "annotations": [], "callers": [], "uses_fields": []}}
        self.assertFalse(self._provenance(bundle)["graph_context_populated"])

    def test_graph_context_populated_true_from_calls(self) -> None:
        bundle = {"graph_context": {"calls": ["com.example.Foo.bar()"], "annotations": [], "callers": [], "uses_fields": []}}
        self.assertTrue(self._provenance(bundle)["graph_context_populated"])

    def test_graph_context_populated_true_from_annotations(self) -> None:
        bundle = {"graph_context": {"calls": [], "annotations": ["GetMapping"], "callers": [], "uses_fields": []}}
        self.assertTrue(self._provenance(bundle)["graph_context_populated"])

    def test_graph_context_populated_false_when_absent(self) -> None:
        self.assertFalse(self._provenance({})["graph_context_populated"])

    # ------------------------------------------------------------------
    # source_snippet_resolved
    # ------------------------------------------------------------------

    def test_source_snippet_false_when_empty(self) -> None:
        self.assertFalse(self._provenance({"source_code": ""})["source_snippet_resolved"])

    def test_source_snippet_false_when_absent(self) -> None:
        self.assertFalse(self._provenance({})["source_snippet_resolved"])

    def test_source_snippet_true_when_present(self) -> None:
        bundle = {"source_code": "MessageDigest.getInstance(\"MD5\");"}
        self.assertTrue(self._provenance(bundle)["source_snippet_resolved"])

    # ------------------------------------------------------------------
    # analysis_flags_active
    # ------------------------------------------------------------------

    def test_analysis_flags_active_empty_when_no_flags(self) -> None:
        self.assertEqual(self._provenance({})["analysis_flags_active"], [])

    def test_analysis_flags_active_excludes_false_flags(self) -> None:
        bundle = {"analysis_flags": {"md5_detected": False, "weak_hash_detected": False}}
        self.assertEqual(self._provenance(bundle)["analysis_flags_active"], [])

    def test_analysis_flags_active_includes_true_flags(self) -> None:
        bundle = {"analysis_flags": {"md5_detected": True, "weak_hash_detected": False, "insecure_random_detected": True}}
        active = self._provenance(bundle)["analysis_flags_active"]
        self.assertIn("md5_detected", active)
        self.assertIn("insecure_random_detected", active)
        self.assertNotIn("weak_hash_detected", active)

    # ------------------------------------------------------------------
    # vector_context_available
    # ------------------------------------------------------------------

    def test_vector_context_false_when_empty(self) -> None:
        self.assertFalse(self._provenance({"vector_context": []})["vector_context_available"])

    def test_vector_context_true_when_present(self) -> None:
        bundle = {"vector_context": ["com.example.Similar.method()"]}
        self.assertTrue(self._provenance(bundle)["vector_context_available"])

    # ------------------------------------------------------------------
    # taint_paths_available
    # ------------------------------------------------------------------

    def test_taint_paths_false_when_absent(self) -> None:
        self.assertFalse(self._provenance({})["taint_paths_available"])

    def test_taint_paths_false_when_empty_list(self) -> None:
        self.assertFalse(self._provenance({"taint_paths": []})["taint_paths_available"])

    def test_taint_paths_true_when_present(self) -> None:
        bundle = {"taint_paths": [{"sink_type": "sql", "hops": 2}]}
        self.assertTrue(self._provenance(bundle)["taint_paths_available"])

    # ------------------------------------------------------------------
    # Existing fields are unchanged (non-regression)
    # ------------------------------------------------------------------

    def test_existing_evidence_fields_unchanged(self) -> None:
        bundle = {
            "source_code": "String x = getParameter(\"x\");",
            "graph_context": {"calls": ["Foo.bar()"], "annotations": [], "callers": [], "uses_fields": []},
            "vector_context": ["Baz.qux()"],
            "file_path": "/src/Foo.java",
            "target_method": "com.example.Foo.doPost()",
            "start_line": 10,
            "end_line": 20,
            "analysis_flags": {"sql_dynamic_query_detected": True},
        }
        result = _build(bundle)["evidence"]
        self.assertEqual(result["source_code"], bundle["source_code"])
        self.assertEqual(result["file_path"], "/src/Foo.java")
        self.assertEqual(result["start_line"], 10)
        self.assertEqual(result["end_line"], 20)
        self.assertEqual(result["graph_context"], bundle["graph_context"])
        self.assertEqual(result["vector_context"], ["Baz.qux()"])
        self.assertEqual(result["analysis_flags"], {"sql_dynamic_query_detected": True})


if __name__ == "__main__":
    unittest.main()
