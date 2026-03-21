import os
import unittest

os.environ.setdefault("NEO4J_PASS", "test-password")

from run_explanation_eval import build_expected_citation, has_exact_citation


class TestRunExplanationEval(unittest.TestCase):
    def test_build_expected_citation_uses_canonical_citation(self) -> None:
        violation = {
            "violation_id": "ISO-A.10-WEAK-HASH",
            "target_method": "org.example.Foo.hash()",
            "file_path": "src/Foo.java",
            "evidence": {
                "file_path": "src/Foo.java",
                "target_method": "org.example.Foo.hash()",
                "start_line": 10,
                "end_line": 18,
                "source_code": "public void hash() {}",
                "graph_context": {"calls": ["MessageDigest.getInstance"]},
                "vector_context": [],
                "analysis_flags": {"weak_hash_detected": True},
            },
        }

        self.assertEqual(
            build_expected_citation(
                violation,
                include_graph_context=True,
                evidence_mode="lean",
            ),
            "src/Foo.java lines 10-18",
        )

    def test_has_exact_citation_accepts_exact_structured_citation(self) -> None:
        self.assertTrue(
            has_exact_citation(
                {
                    "evidence_id": "E1",
                    "citation": "src/Foo.java lines 10-18",
                    "why": "Weak hash is insecure.",
                    "fix": "Use SHA-256.",
                },
                "src/Foo.java lines 10-18",
            )
        )

    def test_has_exact_citation_rejects_file_path_only_overlap(self) -> None:
        self.assertFalse(
            has_exact_citation(
                {
                    "citation": "src/Foo.java",
                    "why": "The file path matches but the line range is missing.",
                    "fix": "Use the cited location exactly.",
                },
                "src/Foo.java lines 10-18",
            )
        )

    def test_has_exact_citation_rejects_wrong_line_range(self) -> None:
        self.assertFalse(
            has_exact_citation(
                {
                    "citation": "src/Foo.java line 10",
                    "why": "This mentions only one line.",
                    "fix": "Use the exact provided range.",
                },
                "src/Foo.java lines 10-18",
            )
        )

    def test_has_exact_citation_rejects_missing_structured_citation(self) -> None:
        self.assertFalse(
            has_exact_citation(
                {
                    "why": "org.example.Foo.hash() appears in the prose, but there is no structured citation.",
                    "fix": "Cite the exact evidence.",
                },
                "src/Foo.java lines 10-18",
            )
        )


if __name__ == "__main__":
    unittest.main()
