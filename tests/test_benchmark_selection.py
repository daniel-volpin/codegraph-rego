import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from codegraph.evaluation.benchmark import (
    CategorySpec,
    CoverageStats,
    GroundTruthRecord,
    coverage_report,
    load_mapping_config,
    select_testcases,
    stage_benchmark_subset,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]


class TestBenchmarkSelectionCoverage(unittest.TestCase):
    def test_policy_registry_categories_drive_cwe_selection(self) -> None:
        categories = load_mapping_config(PROJECT_ROOT / "configs" / "benchmark" / "policy_registry.json")
        by_id = {category.id: category for category in categories}
        self.assertEqual(by_id["sql-injection"].cwes, ["CWE-89"])
        self.assertEqual(by_id["hash-md5"].rego_rules, ["ISO-A.10-WEAK-HASH"])
        self.assertEqual(by_id["crypto-md5"].remediation_tier, "guarded")
        self.assertTrue(by_id["xpath-injection"].framework_demo)

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
            GroundTruthRecord(testcase_id=f"BenchmarkTest{idx:05d}", cwe="CWE-330", label=True) for idx in range(20)
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

    def test_stage_benchmark_subset_copies_compile_scaffold(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            benchmark_root = root / "BenchmarkJava"
            testcase_dir = benchmark_root / "src" / "main" / "java" / "org" / "owasp" / "benchmark" / "testcode"
            helpers_dir = benchmark_root / "src" / "main" / "java" / "org" / "owasp" / "benchmark" / "helpers"
            service_dir = benchmark_root / "src" / "main" / "java" / "org" / "owasp" / "benchmark" / "service" / "pojo"
            resources_dir = benchmark_root / "src" / "main" / "resources"

            testcase_dir.mkdir(parents=True)
            helpers_dir.mkdir(parents=True)
            service_dir.mkdir(parents=True)
            resources_dir.mkdir(parents=True)

            (benchmark_root / "pom.xml").write_text("<project />\n", encoding="utf-8")
            (benchmark_root / "DevStyleHtml.prefs").write_text("html=true\n", encoding="utf-8")
            (benchmark_root / "DevStyleXml.prefs").write_text("xml=true\n", encoding="utf-8")
            (benchmark_root / ".mvn").mkdir(parents=True)
            (resources_dir / "benchmark.properties").write_text("k=v\n", encoding="utf-8")
            (helpers_dir / "Utils.java").write_text("class Utils {}\n", encoding="utf-8")
            (service_dir / "Person.java").write_text("class Person {}\n", encoding="utf-8")
            (testcase_dir / "BenchmarkTest00046.java").write_text("class BenchmarkTest00046 {}\n", encoding="utf-8")

            dest_root = root / "staged"
            staged = stage_benchmark_subset(benchmark_root, "src/main/java", ["BenchmarkTest00046"], dest_root)

            self.assertIn("BenchmarkTest00046", staged)
            self.assertTrue((dest_root / "pom.xml").is_file())
            self.assertTrue((dest_root / "DevStyleHtml.prefs").is_file())
            self.assertTrue((dest_root / "DevStyleXml.prefs").is_file())
            self.assertTrue((dest_root / ".mvn").is_dir())
            self.assertTrue((dest_root / "src" / "main" / "resources" / "benchmark.properties").is_file())
            self.assertTrue(
                (
                    dest_root
                    / "src"
                    / "main"
                    / "java"
                    / "org"
                    / "owasp"
                    / "benchmark"
                    / "helpers"
                    / "Utils.java"
                ).is_file()
            )
            self.assertTrue(
                (
                    dest_root
                    / "src"
                    / "main"
                    / "java"
                    / "org"
                    / "owasp"
                    / "benchmark"
                    / "service"
                    / "pojo"
                    / "Person.java"
                ).is_file()
            )


if __name__ == "__main__":
    unittest.main()
