"""Tests for run_owasp_multiseed_eval.py's pure helpers.

The script-level CLI integration is exercised via smoke-runs in the
PR commit description; here we pin the aggregation helpers that are
amenable to unit testing without spinning up OPA.
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

_PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _load_multiseed_module():
    spec = importlib.util.spec_from_file_location(
        "run_owasp_multiseed_eval",
        _PROJECT_ROOT / "run_owasp_multiseed_eval.py",
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["run_owasp_multiseed_eval"] = module
    spec.loader.exec_module(module)
    return module


class AcrossSeedAggregationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.ms = _load_multiseed_module()

    def test_empty_input_returns_empty_dict(self) -> None:
        out = self.ms._aggregate_across_seeds([])
        self.assertEqual(out, {})

    def test_single_seed_has_zero_stdev(self) -> None:
        per_seed = [
            {"pre_f10": {"tp": 10.0, "fp": 2.0, "tn": 8.0, "fn": 0.0,
                         "precision": 0.833, "recall": 1.0, "f1": 0.909}}
        ]
        out = self.ms._aggregate_across_seeds(per_seed)
        self.assertEqual(out["pre_f10"]["precision"]["stdev"], 0.0)
        self.assertEqual(out["pre_f10"]["precision"]["mean"], 0.833)
        self.assertEqual(out["pre_f10"]["precision"]["min"], 0.833)
        self.assertEqual(out["pre_f10"]["precision"]["max"], 0.833)

    def test_three_seeds_aggregate_mean_min_max(self) -> None:
        per_seed = [
            {"semgrep": {"tp": 1, "fp": 0, "tn": 5, "fn": 4,
                         "precision": 1.0, "recall": 0.2, "f1": 0.333}},
            {"semgrep": {"tp": 2, "fp": 0, "tn": 5, "fn": 3,
                         "precision": 1.0, "recall": 0.4, "f1": 0.571}},
            {"semgrep": {"tp": 3, "fp": 0, "tn": 5, "fn": 2,
                         "precision": 1.0, "recall": 0.6, "f1": 0.750}},
        ]
        out = self.ms._aggregate_across_seeds(per_seed)
        r = out["semgrep"]["recall"]
        self.assertAlmostEqual(r["mean"], 0.4, places=3)
        self.assertEqual(r["min"], 0.2)
        self.assertEqual(r["max"], 0.6)
        # Sample stdev (n−1 denominator): sqrt(((0.2−0.4)^2+(0.4−0.4)^2+(0.6−0.4)^2)/2)
        # = sqrt((0.04+0+0.04)/2) = sqrt(0.04) = 0.2
        self.assertAlmostEqual(r["stdev"], 0.2, places=3)

    def test_markdown_table_renders_methods_and_seeds(self) -> None:
        per_seed = [
            {"pre_f10": {"tp": 10, "fp": 2, "tn": 8, "fn": 0,
                         "precision": 0.833, "recall": 1.0, "f1": 0.909}}
        ]
        agg = self.ms._aggregate_across_seeds(per_seed)
        md = self.ms._format_multi_seed_markdown(
            seeds=[42], per_seed=per_seed, aggregate=agg, limit_per_cwe=50,
        )
        self.assertIn("Across-seed mean ± stdev", md)
        self.assertIn("Per-seed metrics", md)
        self.assertIn("pre_f10", md)


if __name__ == "__main__":
    unittest.main()
