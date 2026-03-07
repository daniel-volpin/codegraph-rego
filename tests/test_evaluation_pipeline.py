import unittest

from codegraph.evaluation.benchmark import CategorySpec, GroundTruthRecord, SelectionResult
from codegraph.evaluation.pipeline import collect_category_violations, group_violations_by_testcase


class TestEvaluationPipeline(unittest.TestCase):
    def test_group_violations_by_testcase_uses_signature_or_file_path(self) -> None:
        violations = [
            {
                "violation_id": "ISO-A.10-WEAK-HASH",
                "target_method": "org.example.BenchmarkTest00001.doPost()",
                "file_path": "ignored.java",
            },
            {
                "violation_id": "ISO-A.10-WEAK-CRYPTO",
                "target_method": None,
                "file_path": "/tmp/BenchmarkTest00002.java",
            },
            {
                "violation_id": "ISO-A.10-WEAK-HASH",
                "target_method": "org.example.Other.doPost()",
                "file_path": "Other.java",
            },
        ]

        grouped = group_violations_by_testcase(violations)

        self.assertEqual(list(grouped.keys()), ["BenchmarkTest00001", "BenchmarkTest00002"])
        self.assertEqual(grouped["BenchmarkTest00001"][0]["violation_id"], "ISO-A.10-WEAK-HASH")
        self.assertEqual(grouped["BenchmarkTest00002"][0]["violation_id"], "ISO-A.10-WEAK-CRYPTO")

    def test_collect_category_violations_filters_positive_cases_and_dedupes(self) -> None:
        category = CategorySpec(
            id="weak-hash",
            label="Weak Hash",
            cwes=["CWE-328"],
            rego_rules=["ISO-A.10-WEAK-HASH"],
        )
        selection = SelectionResult(
            selected_by_category={
                "weak-hash": [
                    GroundTruthRecord(testcase_id="BenchmarkTest00001", cwe="CWE-328", label=True),
                    GroundTruthRecord(testcase_id="BenchmarkTest00002", cwe="CWE-328", label=False),
                ]
            },
            selected_testcase_ids=["BenchmarkTest00001", "BenchmarkTest00002"],
        )
        shared_violation = {
            "violation_id": "ISO-A.10-WEAK-HASH",
            "target_method": "org.example.BenchmarkTest00001.doPost()",
            "file_path": "BenchmarkTest00001.java",
        }
        violations_by_testcase = {
            "BenchmarkTest00001": [
                shared_violation,
                dict(shared_violation),
                {
                    "violation_id": "ISO-A.10-WEAK-CRYPTO",
                    "target_method": "org.example.BenchmarkTest00001.doPost()",
                    "file_path": "BenchmarkTest00001.java",
                },
            ],
            "BenchmarkTest00002": [
                {
                    "violation_id": "ISO-A.10-WEAK-HASH",
                    "target_method": "org.example.BenchmarkTest00002.doPost()",
                    "file_path": "BenchmarkTest00002.java",
                }
            ],
        }

        category_violations = collect_category_violations(
            selected_category_ids=["weak-hash"],
            categories_by_id={"weak-hash": category},
            selection=selection,
            violations_by_testcase=violations_by_testcase,
        )

        self.assertEqual(len(category_violations["weak-hash"]), 1)
        self.assertEqual(category_violations["weak-hash"][0]["target_method"], shared_violation["target_method"])


if __name__ == "__main__":
    unittest.main()
