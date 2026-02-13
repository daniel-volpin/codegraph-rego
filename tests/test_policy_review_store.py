import json
import unittest
from pathlib import Path


class TestPolicyReviewStore(unittest.TestCase):
    def test_append_review_writes_jsonl(self) -> None:
        from codegraph.policy.review_store import append_review_jsonl

        out = Path("outputs/test_policy_ui_reviews")
        out.mkdir(parents=True, exist_ok=True)
        store_path = (out / "reviews.jsonl").as_posix()

        result = append_review_jsonl(
            store_path=store_path,
            label="TP",
            notes="ok",
            violation={
                "violation_id": "ISO-A.10-WEAK-HASH",
                "target_method": "org.example.Foo.doPost()",
                "file_path": "Example.java",
                "evidence": {"source_code": "class Foo {}", "graph_context": {}, "vector_context": []},
            },
            explanation="explanation",
            llm_model="dummy",
            include_graph_context=True,
            remediation_preview=None,
            remediation_apply=None,
        )

        self.assertEqual(result.status, "OK")
        self.assertTrue(result.review_id)
        self.assertTrue(result.store_path)
        self.assertTrue(Path(result.store_path).is_file())

        last_line = Path(result.store_path).read_text(encoding="utf-8").strip().splitlines()[-1]
        payload = json.loads(last_line)
        self.assertEqual(payload["label"], "TP")
        self.assertEqual(payload["violation_key"], "ISO-A.10-WEAK-HASH::org.example.Foo.doPost()::Example.java")

    def test_oversized_explanation_gets_truncated(self) -> None:
        from codegraph.policy.review_store import append_review_jsonl, MAX_STRING_CHARS

        out = Path("outputs/test_policy_ui_reviews")
        out.mkdir(parents=True, exist_ok=True)
        store_path = (out / "reviews.jsonl").as_posix()

        huge = "x" * (MAX_STRING_CHARS + 1000)
        result = append_review_jsonl(
            store_path=store_path,
            label="FP",
            notes=None,
            violation={"violation_id": "X", "target_method": "m", "file_path": "f"},
            explanation=huge,
            llm_model="dummy",
            include_graph_context=True,
        )
        self.assertEqual(result.status, "OK")
        self.assertTrue(result.scrub_warnings)
        self.assertTrue(any(w == "truncated_string:$.llm.explanation" for w in result.scrub_warnings))

        last_line = Path(result.store_path).read_text(encoding="utf-8").strip().splitlines()[-1]
        payload = json.loads(last_line)
        self.assertLessEqual(len(payload["llm"]["explanation"]), MAX_STRING_CHARS)
        self.assertTrue(any("truncated_string" in w for w in result.scrub_warnings))

    def test_remediation_arrays_are_summarized(self) -> None:
        from codegraph.policy.review_store import append_review_jsonl

        out = Path("outputs/test_policy_ui_reviews")
        out.mkdir(parents=True, exist_ok=True)
        store_path = (out / "reviews.jsonl").as_posix()

        result = append_review_jsonl(
            store_path=store_path,
            label="TP",
            notes=None,
            violation={"violation_id": "X", "target_method": "m", "file_path": "f"},
            explanation=None,
            llm_model="dummy",
            include_graph_context=True,
            remediation_apply={
                "status": "OK",
                "rule_id": "R",
                "verification": {
                    "overall_status": "PASS",
                    "target_rule_status": "PASS",
                    "baseline": [{"a": 1}] * 500,
                    "after": [{"b": 2}] * 400,
                    "new_violations": [{"c": 3}] * 2,
                    "remaining_violations": [{"d": 4}] * 3,
                },
                "compilation": {"attempted": True, "success": True, "output_snippet": "nope"},
                "updated_source_code": "big",
                "diff": "big",
            },
        )
        self.assertEqual(result.status, "OK")
        last_line = Path(result.store_path).read_text(encoding="utf-8").strip().splitlines()[-1]
        payload = json.loads(last_line)
        apply_summary = payload.get("remediation", {}).get("apply", {})
        self.assertEqual(apply_summary.get("baseline_count"), 500)
        self.assertNotIn("baseline", apply_summary)
        self.assertIn("compilation", apply_summary)
        self.assertNotIn("output_snippet", apply_summary.get("compilation", {}))

    def test_unsafe_path_is_rejected(self) -> None:
        from codegraph.policy.review_store import append_review_jsonl

        result = append_review_jsonl(
            store_path="/tmp/policy_ui_reviews.jsonl",
            label="TP",
            notes=None,
            violation={"violation_id": "X"},
            explanation=None,
            llm_model="dummy",
            include_graph_context=True,
        )
        self.assertEqual(result.status, "ERROR")
        self.assertTrue(result.error and "unsafe_store_path_outside_outputs" in result.error)


if __name__ == "__main__":
    unittest.main()
