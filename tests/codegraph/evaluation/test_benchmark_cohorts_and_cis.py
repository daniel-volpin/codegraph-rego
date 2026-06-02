"""TP/FP cohort split and CI wiring in ``run_benchmark_eval``.

Covers the additive surfaces only; point estimates are unchanged.
"""

from __future__ import annotations

# `score_category` lives at the script top-level; importing the script module
# triggers `argparse` only inside `main()`, so this is safe.
import importlib.util
import json
import pathlib
import tempfile
import unittest

from codegraph.evaluation.benchmark import (
    CategorySpec,
    GroundTruthRecord,
    SelectionResult,
)
from codegraph.evaluation.explanation_runtime import ExplanationRuntime
from codegraph.evaluation.pipeline import (
    collect_category_false_positive_violations,
    collect_category_violations,
)

_SCRIPT_PATH = pathlib.Path(__file__).resolve().parents[3] / "run_benchmark_eval.py"
_spec = importlib.util.spec_from_file_location("_run_benchmark_eval", _SCRIPT_PATH)
_module = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(_module)
score_category = _module.score_category


def _spec(rule_id: str, cwes: list[str]) -> CategorySpec:
    return CategorySpec(
        id="cat",
        label="Cat",
        cwes=cwes,
        rego_rules=[rule_id],
    )


class TestScoreCategoryWithCIs(unittest.TestCase):
    def test_perfect_classifier_emits_unit_intervals(self) -> None:
        spec = _spec("R1", ["CWE-78"])
        ground_truth = {"t1": True, "t2": True, "t3": False, "t4": False}
        testcases = list(ground_truth.keys())
        violations_by_testcase = {
            "t1": [{"violation_id": "R1"}],
            "t2": [{"violation_id": "R1"}],
        }
        stats = score_category(spec, ground_truth, testcases, violations_by_testcase, ci_seed=1)
        self.assertEqual(stats["tp"], 2)
        self.assertEqual(stats["fp"], 0)
        self.assertEqual(stats["fn"], 0)
        self.assertEqual(stats["precision"], 1.0)
        self.assertEqual(stats["recall"], 1.0)
        self.assertEqual(stats["f1"], 1.0)
        # CI fields are present and bracket the point estimate.
        for key in ("precision_ci", "recall_ci", "f1_ci"):
            ci = stats[key]
            self.assertIn("point", ci)
            self.assertIn("ci_low", ci)
            self.assertIn("ci_high", ci)
            self.assertLessEqual(ci["ci_low"], ci["point"])
            self.assertGreaterEqual(ci["ci_high"], ci["point"])
        # Wilson sanity-check fields.
        self.assertIn("precision_ci_wilson", stats)
        self.assertIn("recall_ci_wilson", stats)

    def test_seed_makes_ci_deterministic(self) -> None:
        spec = _spec("R1", ["CWE-78"])
        ground_truth = {f"t{i}": (i % 2 == 0) for i in range(20)}
        testcases = list(ground_truth.keys())
        # Mark every other case as predicted to produce a non-trivial split.
        violations_by_testcase = {
            tid: [{"violation_id": "R1"}] for i, tid in enumerate(testcases) if i % 3 == 0
        }
        a = score_category(spec, ground_truth, testcases, violations_by_testcase, ci_seed=42)
        b = score_category(spec, ground_truth, testcases, violations_by_testcase, ci_seed=42)
        self.assertEqual(a["precision_ci"], b["precision_ci"])
        self.assertEqual(a["recall_ci"], b["recall_ci"])
        self.assertEqual(a["f1_ci"], b["f1_ci"])


class TestCollectCohortSplit(unittest.TestCase):
    def _selection(self) -> SelectionResult:
        records = [
            GroundTruthRecord(testcase_id="t1", cwe="CWE-89", label=True),
            GroundTruthRecord(testcase_id="t2", cwe="CWE-89", label=True),
            GroundTruthRecord(testcase_id="t3", cwe="CWE-89", label=False),
            GroundTruthRecord(testcase_id="t4", cwe="CWE-89", label=False),
        ]
        return SelectionResult(
            selected_by_category={"sql": records},
            selected_testcase_ids=["t1", "t2", "t3", "t4"],
        )

    def _violations_by_testcase(self) -> dict[str, list[dict]]:
        return {
            "t1": [{"violation_id": "ISO-A.8-SQL-INJECTION", "target_method": "x", "file_path": "/a"}],
            "t3": [{"violation_id": "ISO-A.8-SQL-INJECTION", "target_method": "y", "file_path": "/b"}],
        }

    def test_tp_cohort_excludes_negatives(self) -> None:
        spec = CategorySpec(
            id="sql", label="SQL", cwes=["CWE-89"], rego_rules=["ISO-A.8-SQL-INJECTION"]
        )
        result = collect_category_violations(
            selected_category_ids=["sql"],
            categories_by_id={"sql": spec},
            selection=self._selection(),
            violations_by_testcase=self._violations_by_testcase(),
        )
        self.assertEqual(len(result["sql"]), 1)
        self.assertEqual(result["sql"][0]["target_method"], "x")

    def test_fp_cohort_excludes_positives(self) -> None:
        spec = CategorySpec(
            id="sql", label="SQL", cwes=["CWE-89"], rego_rules=["ISO-A.8-SQL-INJECTION"]
        )
        result = collect_category_false_positive_violations(
            selected_category_ids=["sql"],
            categories_by_id={"sql": spec},
            selection=self._selection(),
            violations_by_testcase=self._violations_by_testcase(),
        )
        self.assertEqual(len(result["sql"]), 1)
        self.assertEqual(result["sql"][0]["target_method"], "y")

    def test_cohorts_partition_violations(self) -> None:
        """For a fixed violation set, every violation is in either cohort exactly once."""
        spec = CategorySpec(
            id="sql", label="SQL", cwes=["CWE-89"], rego_rules=["ISO-A.8-SQL-INJECTION"]
        )
        tp = collect_category_violations(
            selected_category_ids=["sql"],
            categories_by_id={"sql": spec},
            selection=self._selection(),
            violations_by_testcase=self._violations_by_testcase(),
        )
        fp = collect_category_false_positive_violations(
            selected_category_ids=["sql"],
            categories_by_id={"sql": spec},
            selection=self._selection(),
            violations_by_testcase=self._violations_by_testcase(),
        )
        tp_keys = {v["target_method"] for v in tp["sql"]}
        fp_keys = {v["target_method"] for v in fp["sql"]}
        self.assertEqual(tp_keys & fp_keys, set())  # disjoint
        self.assertEqual(tp_keys | fp_keys, {"x", "y"})  # complete


class TestExplanationProgressCohorts(unittest.TestCase):
    def test_fp_progress_does_not_change_tp_headline_totals(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            runtime = ExplanationRuntime(
                output_dir=pathlib.Path(tmpdir),
                benchmark_root=pathlib.Path(tmpdir),
                truth_path=pathlib.Path(tmpdir) / "truth.csv",
                truth_schema={},
                selection_cfg={},
                coverage_by_category={},
                sample_per_category=0,
            )
            metrics: dict = {}
            runtime.begin_explanations(total_target_violations=2, metrics=metrics)
            runtime.start_category("sql", "SQL", 2, metrics)
            runtime.record_violation_result(True, False, metrics)
            runtime.record_nonheadline_violation_result(metrics)
            runtime.finalize("completed", metrics)

            progress = json.loads((pathlib.Path(tmpdir) / "progress.json").read_text())
            self.assertEqual(progress["processed_violations"], 2)
            self.assertEqual(progress["total_violations"], 2)
            self.assertEqual(progress["percent_complete"], 1.0)
            self.assertEqual(progress["overall_partial"]["with_context"], 1)
            self.assertEqual(progress["overall_partial"]["without_context"], 0)


if __name__ == "__main__":
    unittest.main()
