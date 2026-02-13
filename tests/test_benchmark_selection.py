import unittest

from codegraph.evaluation.benchmark import (
    CategorySpec,
    CoverageStats,
    GroundTruthRecord,
    coverage_report,
    select_testcases,
)


class TestBenchmarkSelectionCoverage(unittest.TestCase):
    def test_full_selection_no_sampling_limit_returns_all_cases(self) -> None:
        records = [
            GroundTruthRecord(testcase_id=f"BenchmarkTest{idx:05d}", cwe="CWE-89", label=bool(idx % 2))
            for idx in range(10)
        ]
        categories = [
            CategorySpec(
                id="sql-injection",
                label="SQL Injection (CWE-89)",
                cwes=["CWE-89"],
                rego_rules=["ISO-A.8-SQL-INJECTION"],
            )
        ]
        selection_cfg = {
            "categories": ["sql-injection"],
            "testcase_ids": [],
            "max_cases_per_category": 0,  # explicit "no limit"
            "seed": 7,
        }
        selection = select_testcases(records, categories, selection_cfg)
        self.assertEqual(len(selection.selected_by_category["sql-injection"]), 10)
        stats = selection.coverage_by_category["sql-injection"]
        self.assertIsInstance(stats, CoverageStats)
        self.assertEqual(stats.available_cases, 10)
        self.assertEqual(stats.selected_cases, 10)
        self.assertFalse(stats.sampled)

        report = coverage_report(selection, ["sql-injection"])
        self.assertEqual(
            report["sql-injection"],
            {"available_cases": 10, "selected_cases": 10, "sampled": False},
        )

    def test_sampling_is_deterministic_when_enabled(self) -> None:
        records = [
            GroundTruthRecord(testcase_id=f"BenchmarkTest{idx:05d}", cwe="CWE-330", label=True)
            for idx in range(20)
        ]
        categories = [
            CategorySpec(
                id="rng-insecure",
                label="Randomness (CWE-330)",
                cwes=["CWE-330"],
                rego_rules=["ISO-A.10-WEAK-RANDOM"],
            )
        ]
        selection_cfg = {
            "categories": ["rng-insecure"],
            "testcase_ids": [],
            "max_cases_per_category": 5,
            "seed": 123,
        }
        sel1 = select_testcases(records, categories, selection_cfg)
        sel2 = select_testcases(records, categories, selection_cfg)
        self.assertEqual(sel1.selected_testcase_ids, sel2.selected_testcase_ids)
        stats = sel1.coverage_by_category["rng-insecure"]
        self.assertEqual(stats.available_cases, 20)
        self.assertEqual(stats.selected_cases, 5)
        self.assertTrue(stats.sampled)


if __name__ == "__main__":
    unittest.main()

