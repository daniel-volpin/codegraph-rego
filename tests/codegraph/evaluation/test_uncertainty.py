"""Tests for codegraph/evaluation/uncertainty.py.

These intervals back the headline detection metrics in the thesis chapter
Contract: closed-form Wilson for proportions and percentile bootstrap
for F1, both deterministic given a seed.
"""

from __future__ import annotations

import unittest

from codegraph.evaluation.uncertainty import (
    bootstrap_metric_ci,
    bootstrap_paired_delta_ci,
    bootstrap_prf_ci,
    f1_from_outcomes,
    paired_classifier_mcnemar,
    precision_from_outcomes,
    recall_from_outcomes,
    wilson_score_ci,
)


class TestWilsonScoreCI(unittest.TestCase):
    def test_zero_trials_returns_full_unit_interval(self) -> None:
        ci = wilson_score_ci(0, 0)
        self.assertEqual(ci["point"], 0.0)
        self.assertEqual(ci["ci_low"], 0.0)
        self.assertEqual(ci["ci_high"], 1.0)
        self.assertEqual(ci["n"], 0)
        self.assertEqual(ci["method"], "wilson")

    def test_known_values_50_of_100_at_95(self) -> None:
        ci = wilson_score_ci(50, 100, confidence=0.95)
        self.assertEqual(ci["point"], 0.5)
        # Reference: scipy's proportion_confint returns [0.404, 0.596] (rounded).
        self.assertAlmostEqual(ci["ci_low"], 0.4038, places=3)
        self.assertAlmostEqual(ci["ci_high"], 0.5962, places=3)

    def test_boundary_at_one_does_not_exceed_one(self) -> None:
        ci = wilson_score_ci(10, 10)
        self.assertEqual(ci["point"], 1.0)
        self.assertLess(ci["ci_low"], 1.0)
        # Floating-point residual may leave ci_high ~1 - 1e-16; never above 1.
        self.assertLessEqual(ci["ci_high"], 1.0)
        self.assertAlmostEqual(ci["ci_high"], 1.0, places=12)

    def test_boundary_at_zero_does_not_go_below_zero(self) -> None:
        ci = wilson_score_ci(0, 10)
        self.assertEqual(ci["point"], 0.0)
        self.assertEqual(ci["ci_low"], 0.0)
        self.assertGreater(ci["ci_high"], 0.0)

    def test_invalid_inputs_raise(self) -> None:
        with self.assertRaises(ValueError):
            wilson_score_ci(-1, 10)
        with self.assertRaises(ValueError):
            wilson_score_ci(11, 10)
        with self.assertRaises(ValueError):
            wilson_score_ci(0, -1)
        with self.assertRaises(ValueError):
            wilson_score_ci(0, 10, confidence=0.0)
        with self.assertRaises(ValueError):
            wilson_score_ci(0, 10, confidence=1.0)


class TestPerCaseMetrics(unittest.TestCase):
    def test_perfect_classifier(self) -> None:
        outcomes = [(True, True)] * 5 + [(False, False)] * 5
        self.assertEqual(precision_from_outcomes(outcomes), 1.0)
        self.assertEqual(recall_from_outcomes(outcomes), 1.0)
        self.assertEqual(f1_from_outcomes(outcomes), 1.0)

    def test_all_false_positives(self) -> None:
        outcomes = [(True, False)] * 5 + [(False, False)] * 5
        self.assertEqual(precision_from_outcomes(outcomes), 0.0)
        self.assertEqual(recall_from_outcomes(outcomes), 0.0)
        self.assertEqual(f1_from_outcomes(outcomes), 0.0)

    def test_mixed_outcomes(self) -> None:
        # 3 TP, 1 FP, 1 FN, 5 TN  -> P=0.75, R=0.75, F1=0.75
        outcomes = [(True, True)] * 3 + [(True, False)] + [(False, True)] + [(False, False)] * 5
        self.assertAlmostEqual(precision_from_outcomes(outcomes), 0.75)
        self.assertAlmostEqual(recall_from_outcomes(outcomes), 0.75)
        self.assertAlmostEqual(f1_from_outcomes(outcomes), 0.75)


class TestBootstrapMetricCI(unittest.TestCase):
    def test_seeded_run_is_deterministic(self) -> None:
        outcomes = [(True, True)] * 30 + [(False, False)] * 30 + [(True, False)] * 5
        a = bootstrap_metric_ci(outcomes, f1_from_outcomes, n_resamples=200, seed=11)
        b = bootstrap_metric_ci(outcomes, f1_from_outcomes, n_resamples=200, seed=11)
        self.assertEqual(a, b)

    def test_point_estimate_matches_metric(self) -> None:
        outcomes = [(True, True)] * 7 + [(False, False)] * 3
        result = bootstrap_metric_ci(outcomes, precision_from_outcomes, n_resamples=200, seed=1)
        self.assertEqual(result["point"], precision_from_outcomes(outcomes))
        self.assertLessEqual(result["ci_low"], result["point"])
        self.assertGreaterEqual(result["ci_high"], result["point"])

    def test_empty_outcomes_returns_unit_interval(self) -> None:
        result = bootstrap_metric_ci([], f1_from_outcomes, n_resamples=200, seed=0)
        self.assertEqual(result["n"], 0)
        self.assertEqual(result["ci_low"], 0.0)
        self.assertEqual(result["ci_high"], 1.0)

    def test_invalid_resamples_raises(self) -> None:
        with self.assertRaises(ValueError):
            bootstrap_metric_ci([(True, True)], f1_from_outcomes, n_resamples=0)
        with self.assertRaises(ValueError):
            bootstrap_metric_ci([(True, True)], f1_from_outcomes, confidence=1.5)


class TestBootstrapPRF(unittest.TestCase):
    def test_returns_three_metric_summaries(self) -> None:
        outcomes = [(True, True)] * 20 + [(True, False)] * 5 + [(False, True)] * 3 + [(False, False)] * 12
        result = bootstrap_prf_ci(outcomes, n_resamples=300, seed=42)
        self.assertEqual(set(result.keys()), {"precision", "recall", "f1"})
        for key in ("precision", "recall", "f1"):
            entry = result[key]
            self.assertEqual(entry["method"], "bootstrap_percentile")
            self.assertEqual(entry["n"], len(outcomes))
            self.assertLessEqual(entry["ci_low"], entry["point"])
            self.assertGreaterEqual(entry["ci_high"], entry["point"])

    def test_deterministic_under_seed(self) -> None:
        outcomes = [(True, True)] * 4 + [(False, False)] * 4 + [(True, False)]
        a = bootstrap_prf_ci(outcomes, n_resamples=150, seed=7)
        b = bootstrap_prf_ci(outcomes, n_resamples=150, seed=7)
        self.assertEqual(a, b)


class PairedClassifierMcnemarTests(unittest.TestCase):
    """Exact-binomial McNemar's test for paired classifier comparison."""

    def test_eight_clean_improvements_zero_regressions_is_significant(self) -> None:
        """The canonical LexicalNoiseJava signature: classifier A fires on 8
        comment-stratum NEG cases, classifier B does not — and no regressions.
        Two-sided exact p = 2 * 0.5^8 ≈ 0.0078, well below α=0.05.
        """
        paired = [(True, False, False)] * 8  # 8 FP-class improvements, 0 regressions
        result = paired_classifier_mcnemar(paired, restrict_to="fp_class")
        self.assertEqual(result["b"], 8)
        self.assertEqual(result["c"], 0)
        self.assertEqual(result["n_disagreements"], 8)
        self.assertTrue(result["test_defined"])
        self.assertAlmostEqual(result["p_value"], 2 * 0.5**8, places=6)
        self.assertLess(result["p_value"], 0.05)

    def test_zero_disagreements_returns_undefined_test(self) -> None:
        """OWASP case: pre_f10 and post_f10 agree on every case. b = c = 0;
        McNemar test is undefined."""
        paired = [(True, True, True)] * 200 + [(False, False, False)] * 185
        result = paired_classifier_mcnemar(paired)
        self.assertFalse(result["test_defined"])
        self.assertIsNone(result["p_value"])
        self.assertEqual(result["n_disagreements"], 0)

    def test_symmetric_disagreement_yields_p_value_one(self) -> None:
        """Equal b and c means no directional evidence — p-value is 1.0."""
        paired = [(True, False, False)] * 5 + [(False, True, False)] * 5
        result = paired_classifier_mcnemar(paired)
        self.assertEqual(result["b"], 5)
        self.assertEqual(result["c"], 5)
        self.assertAlmostEqual(result["p_value"], 1.0)

    def test_restrict_to_fp_class_ignores_positives(self) -> None:
        """Only label=False cases count toward the FP-class test."""
        paired = [(True, False, False)] * 4 + [(True, False, True)] * 100
        result = paired_classifier_mcnemar(paired, restrict_to="fp_class")
        self.assertEqual(result["n_disagreements"], 4)

    def test_restrict_to_fn_class_ignores_negatives(self) -> None:
        paired = [(True, False, True)] * 4 + [(True, False, False)] * 100
        result = paired_classifier_mcnemar(paired, restrict_to="fn_class")
        self.assertEqual(result["n_disagreements"], 4)

    def test_invalid_restrict_to_raises(self) -> None:
        with self.assertRaises(ValueError):
            paired_classifier_mcnemar([], restrict_to="not_a_label_class")


class PairedDeltaCITests(unittest.TestCase):
    """Paired bootstrap CI for ΔFPR / ΔFNR (post − pre)."""

    def test_fpr_delta_is_negative_when_b_eliminates_fps(self) -> None:
        """Pre fires on every NEG, post fires on none. ΔFPR should be ≈ -1.0
        and the CI should NOT cross zero."""
        paired = [(True, False, False)] * 25  # 25 NEGs, all cleaned
        result = bootstrap_paired_delta_ci(
            paired, metric="fpr", n_resamples=500, seed=0
        )
        self.assertAlmostEqual(result["point"], -1.0, places=2)
        self.assertLess(result["ci_high"], 0.0, msg="CI must not cross zero")
        self.assertEqual(result["metric"], "delta_fpr")

    def test_fnr_delta_is_zero_when_recall_unchanged(self) -> None:
        """Pre and post both catch every POS. ΔFNR ≈ 0."""
        paired = [(True, True, True)] * 5
        result = bootstrap_paired_delta_ci(
            paired, metric="fnr", n_resamples=200, seed=0
        )
        self.assertEqual(result["point"], 0.0)

    def test_deterministic_under_seed(self) -> None:
        paired = (
            [(True, False, False)] * 4
            + [(False, True, False)] * 2
            + [(True, True, True)] * 3
        )
        a = bootstrap_paired_delta_ci(paired, metric="fpr", n_resamples=200, seed=42)
        b = bootstrap_paired_delta_ci(paired, metric="fpr", n_resamples=200, seed=42)
        self.assertEqual(a, b)

    def test_invalid_metric_raises(self) -> None:
        with self.assertRaises(ValueError):
            bootstrap_paired_delta_ci([], metric="precision_delta")

    def test_empty_returns_zero_metric(self) -> None:
        result = bootstrap_paired_delta_ci([], metric="fpr", n_resamples=10, seed=0)
        self.assertEqual(result["point"], 0.0)
        self.assertEqual(result["n"], 0)


if __name__ == "__main__":
    unittest.main()
