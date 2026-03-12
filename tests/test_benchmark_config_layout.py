import unittest
from pathlib import Path

from codegraph.evaluation.benchmark import load_selection_config


PROJECT_ROOT = Path(__file__).resolve().parents[1]
EXPANDED_BENCHMARK_CATEGORIES = {
    "crypto-md5",
    "hash-md5",
    "rng-insecure",
    "sql-injection",
    "path-traversal",
    "command-injection",
    "ldap-injection",
    "xpath-injection",
}


class TestBenchmarkConfigLayout(unittest.TestCase):
    def test_canonical_benchmark_configs_parse(self) -> None:
        benchmark_dir = PROJECT_ROOT / "configs" / "benchmark"
        expected = {
            "baseline.json",
            "smoke_mixed.json",
            "multicat_medium.json",
            "multicat_full.json",
            "expanded_eval.json",
            "framework_demo.json",
            "remediation_hash_smoke.json",
            "remediation_bounded_smoke.json",
            "remediation_supported_medium.json",
            "policy_registry.json",
        }
        actual = {path.name for path in benchmark_dir.glob("*.json")}
        self.assertTrue(expected.issubset(actual))

        selection_configs = expected - {"policy_registry.json"}
        for name in selection_configs:
            payload = load_selection_config(benchmark_dir / name)
            self.assertIn("benchmark_root", payload)
            self.assertIn("categories", payload)
            self.assertIn("build_command", payload)

        medium_payload = load_selection_config(benchmark_dir / "multicat_medium.json")
        self.assertEqual(set(medium_payload["categories"]), EXPANDED_BENCHMARK_CATEGORIES)
        self.assertEqual(medium_payload["max_cases_per_category"], 20)

        full_payload = load_selection_config(benchmark_dir / "multicat_full.json")
        self.assertEqual(set(full_payload["categories"]), EXPANDED_BENCHMARK_CATEGORIES)
        self.assertEqual(full_payload["max_cases_per_category"], 60)

    def test_legacy_benchmark_selection_configs_are_absent(self) -> None:
        configs_dir = PROJECT_ROOT / "configs"
        legacy_paths = [
            configs_dir / "benchmark_selection.example.json",
            configs_dir / "benchmark_selection.multicat.json",
            configs_dir / "benchmark_selection.pinned_33089.json",
            configs_dir / "benchmark_selection.multicat_full.json",
            configs_dir / "benchmark_selection.multicat_medium.json",
            configs_dir / "benchmark_selection.framework_demo.json",
            configs_dir / "benchmark_selection.expanded_eval.json",
            configs_dir / "benchmark_selection.remediation_cwe328_smoke.json",
            configs_dir / "benchmark_selection.smoke_mixed.json",
        ]
        for path in legacy_paths:
            self.assertFalse(path.exists(), path.name)


if __name__ == "__main__":
    unittest.main()
