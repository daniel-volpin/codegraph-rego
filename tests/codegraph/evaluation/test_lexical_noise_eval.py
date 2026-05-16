"""Tests for the LexicalNoiseJava detection eval (Phase D of F10)."""

from __future__ import annotations

import shutil
import unittest
from pathlib import Path

from baselines.semgrep.runner import (
    SemgrepFinding,
    SemgrepNotInstalledError,
    SemgrepRunResult,
    run_semgrep_baseline,
)
from codegraph.evaluation.lexical_noise import (
    LexicalNoiseCase,
    load_lexical_noise_manifest,
)
from codegraph.evaluation.lexical_noise_eval import (
    METHODS,
    MethodMetrics,
    _build_minimal_bundle,
    _extract_target_method,
    detect_via_semgrep,
    evaluate_benchmark,
    format_markdown_summary,
)


PROJECT_ROOT = Path(__file__).resolve().parents[3]
MANIFEST_PATH = PROJECT_ROOT / "configs" / "benchmark" / "lexical_noise_v1.json"


def _opa_available() -> bool:
    return shutil.which("opa") is not None


def _semgrep_available() -> bool:
    if shutil.which("semgrep"):
        return True
    return (PROJECT_ROOT / ".venv" / "bin" / "semgrep").is_file()


class ExtractTargetMethodTests(unittest.TestCase):
    def test_extracts_method_name_and_param_types(self) -> None:
        source = (
            "public class L02 {\n"
            "    public ResultSet lookup(Connection conn, HttpServletRequest req) "
            "throws Exception {\n"
            "        return null;\n"
            "    }\n"
            "}\n"
        )
        sig = _extract_target_method("L02", source)
        self.assertEqual(
            sig, "com.codegraph.lexicalnoise.L02.lookup(Connection,HttpServletRequest)"
        )

    def test_skips_class_declaration(self) -> None:
        source = (
            "public class L01 {\n"
            "    public byte[] hash(String input) throws Exception {\n"
            "        return null;\n"
            "    }\n"
            "}\n"
        )
        sig = _extract_target_method("L01", source)
        self.assertEqual(sig, "com.codegraph.lexicalnoise.L01.hash(String)")

    def test_falls_back_for_no_public_method(self) -> None:
        sig = _extract_target_method("Lxx", "package x;\nclass X {}\n")
        self.assertEqual(sig, "com.codegraph.lexicalnoise.Lxx.unknown()")

    def test_ignores_method_signature_inside_comment(self) -> None:
        """A commented-out signature must not produce a synthetic target_method.

        Without comment-stripping the regex would happily extract the
        signature from inside a ``//`` line, fabricating a method that
        doesn't exist in the active code. F10's active-view lexer is
        applied before the regex so this can't happen.
        """

        source = (
            "public class L99 {\n"
            "    // public void fake(HttpServletRequest req) { ... }\n"
            "    public int real() { return 0; }\n"
            "}\n"
        )
        sig = _extract_target_method("L99", source)
        self.assertEqual(sig, "com.codegraph.lexicalnoise.L99.real()")

    def test_package_parameter_overrides_default(self) -> None:
        source = (
            "public class BenchmarkTest00001 {\n"
            "    public void doGet(HttpServletRequest req) {}\n"
            "}\n"
        )
        sig = _extract_target_method(
            "BenchmarkTest00001", source, package="org.owasp.benchmark.testcode"
        )
        self.assertEqual(
            sig,
            "org.owasp.benchmark.testcode.BenchmarkTest00001.doGet(HttpServletRequest)",
        )


class BuildBundleTests(unittest.TestCase):
    def test_pre_f10_uses_raw_source_code(self) -> None:
        src = (
            "package p;\npublic class C {\n"
            '    public byte[] f() {\n        // MessageDigest.getInstance("MD5")\n'
            '        return new byte[0];\n    }\n}\n'
        )
        bundle = _build_minimal_bundle(
            src, file_path="a.java", target_method="C.f()", f10_active=False
        )
        self.assertEqual(bundle["source_code"], src)
        self.assertEqual(bundle["source_code_raw"], src)
        self.assertIsInstance(bundle["analysis_flags"], dict)

    def test_post_f10_strips_comments_and_literals_in_source_code(self) -> None:
        src = (
            "package p;\npublic class C {\n"
            '    public byte[] f() {\n        // MessageDigest.getInstance("MD5")\n'
            '        return new byte[0];\n    }\n}\n'
        )
        bundle = _build_minimal_bundle(
            src, file_path="a.java", target_method="C.f()", f10_active=True
        )
        self.assertEqual(bundle["source_code_raw"], src)
        self.assertNotIn("MD5", bundle["source_code"])
        self.assertNotIn("MessageDigest", bundle["source_code"])
        self.assertIsInstance(bundle["analysis_flags"], dict)

    def test_analysis_flags_is_never_omitted(self) -> None:
        # Rego source heuristics gate on `analysis_flags == null` literal —
        # we must set the field, not leave it out.
        for f10_active in (True, False):
            with self.subTest(f10_active=f10_active):
                bundle = _build_minimal_bundle(
                    "package x;", file_path="x.java", target_method="X.f()", f10_active=f10_active
                )
                self.assertIn("analysis_flags", bundle)


class DetectViaSemgrepTests(unittest.TestCase):
    def test_aggregates_only_matching_filename(self) -> None:
        case = LexicalNoiseCase(
            case_id="L06",
            file_name="L06.java",
            fp_source="line_comment",
            expected="positive",
            target_violation_ids=("ISO-A.10-WEAK-HASH",),
            tokens_in_noise=("MD5",),
            rationale="",
        )
        result = SemgrepRunResult(
            findings=(
                SemgrepFinding(
                    rule_id="iso-a10-weak-hash",
                    file_path="x/L06.java",
                    start_line=1,
                    end_line=1,
                    message="",
                ),
                SemgrepFinding(
                    rule_id="iso-a8-sql-injection",
                    file_path="x/L12.java",
                    start_line=1,
                    end_line=1,
                    message="",
                ),
            ),
            rules_path=Path("."),
            target=Path("."),
        )
        detection = detect_via_semgrep(case, result)
        self.assertEqual(detection.fired_violation_ids, ("ISO-A.10-WEAK-HASH",))
        self.assertTrue(detection.target_fired)

    def test_no_match_when_file_absent(self) -> None:
        case = LexicalNoiseCase(
            case_id="L01",
            file_name="L01.java",
            fp_source="line_comment",
            expected="negative",
            target_violation_ids=("ISO-A.10-WEAK-HASH",),
            tokens_in_noise=("MD5",),
            rationale="",
        )
        result = SemgrepRunResult(
            findings=(),
            rules_path=Path("."),
            target=Path("."),
        )
        detection = detect_via_semgrep(case, result)
        self.assertEqual(detection.fired_violation_ids, ())
        self.assertFalse(detection.target_fired)


class MethodMetricsTests(unittest.TestCase):
    def test_perfect_classifier(self) -> None:
        outcomes = [(True, True), (False, False), (True, True), (False, False)]
        m = MethodMetrics.from_outcomes("test", outcomes, n_resamples=100, seed=0)
        self.assertEqual((m.tp, m.fp, m.tn, m.fn), (2, 0, 2, 0))
        self.assertEqual(m.precision, 1.0)
        self.assertEqual(m.recall, 1.0)
        self.assertEqual(m.f1, 1.0)

    def test_only_fps(self) -> None:
        outcomes = [(True, False)] * 5
        m = MethodMetrics.from_outcomes("test", outcomes, n_resamples=50, seed=0)
        self.assertEqual((m.tp, m.fp, m.tn, m.fn), (0, 5, 0, 0))
        self.assertEqual(m.precision, 0.0)
        self.assertEqual(m.recall, 0.0)
        self.assertEqual(m.f1, 0.0)


@unittest.skipUnless(_opa_available(), "opa CLI not installed")
@unittest.skipUnless(_semgrep_available(), "semgrep CLI not installed")
class EvaluateBenchmarkIntegrationTests(unittest.TestCase):
    """End-to-end eval on the 30 LexicalNoiseJava fixtures."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.benchmark = load_lexical_noise_manifest(MANIFEST_PATH)
        try:
            cls.semgrep = run_semgrep_baseline(
                target=cls.benchmark.resolve_fixture_root(PROJECT_ROOT)
            )
        except SemgrepNotInstalledError as exc:
            raise unittest.SkipTest(str(exc))
        cls.report = evaluate_benchmark(
            cls.benchmark, PROJECT_ROOT, cls.semgrep, n_resamples=200, seed=0
        )

    def test_thirty_rows(self) -> None:
        self.assertEqual(self.report.n_cases, 30)
        self.assertEqual(len(self.report.rows), 30)

    def test_all_three_methods_present(self) -> None:
        for method in METHODS:
            self.assertIn(method, self.report.metrics)

    def test_semgrep_baseline_is_perfect(self) -> None:
        sm = self.report.metrics["semgrep"]
        self.assertEqual((sm.tp, sm.fp, sm.tn, sm.fn), (5, 0, 25, 0))
        self.assertEqual(sm.precision, 1.0)
        self.assertEqual(sm.recall, 1.0)
        self.assertEqual(sm.f1, 1.0)

    def test_f10_strictly_improves_precision(self) -> None:
        pre = self.report.metrics["pre_f10"]
        post = self.report.metrics["post_f10"]
        self.assertGreater(
            post.precision,
            pre.precision,
            msg="F10 lexical anchoring must improve precision on LexicalNoiseJava",
        )

    def test_f10_does_not_degrade_recall(self) -> None:
        pre = self.report.metrics["pre_f10"]
        post = self.report.metrics["post_f10"]
        self.assertGreaterEqual(
            post.recall,
            pre.recall,
            msg="F10 lexical anchoring must not reduce recall on LexicalNoiseJava",
        )

    def test_f10_eliminates_all_comment_stratum_fps(self) -> None:
        """Comment-based NEG fixtures must not fire post-F10.

        This is F10's core promise: stripping line and block comments
        from the substring-safe view eliminates any FP whose triggering
        substring lives only in a comment.
        """
        for row in self.report.rows:
            if row.expected != "negative":
                continue
            if row.fp_source not in {"line_comment", "block_comment"}:
                continue
            with self.subTest(case_id=row.case_id):
                self.assertFalse(
                    row.by_method["post_f10"].target_fired,
                    msg=(
                        f"{row.case_id} ({row.fp_source} NEG) fired post-F10 "
                        f"for {row.target_violation_ids} — F10 stripping should "
                        "have eliminated this FP"
                    ),
                )

    def test_at_least_one_pre_f10_fp_per_comment_stratum(self) -> None:
        """The benchmark must be diagnostic: at least one comment-stratum NEG
        must fire pre-F10, otherwise F10's contribution cannot be measured."""

        for stratum in ("line_comment", "block_comment"):
            with self.subTest(stratum=stratum):
                stratum_fps = [
                    row
                    for row in self.report.rows
                    if row.expected == "negative"
                    and row.fp_source == stratum
                    and row.by_method["pre_f10"].target_fired
                ]
                self.assertTrue(
                    stratum_fps,
                    msg=f"No pre-F10 FP fired in stratum {stratum}; benchmark non-diagnostic",
                )

    def test_mcnemar_overall_is_significant_for_f10(self) -> None:
        """Headline statistical claim: post_f10 produces strictly fewer
        firings than pre_f10 on LexicalNoiseJava, with significant
        McNemar p-value (≤ 0.05 at the overall scope).
        """

        overall = next(p for p in self.report.paired if p.scope == "overall")
        self.assertTrue(overall.mcnemar["test_defined"])
        self.assertLessEqual(
            overall.mcnemar["p_value"],
            0.05,
            msg=f"McNemar p = {overall.mcnemar['p_value']:.4f} not significant",
        )
        # Direction: b (pre fired, post didn't) must exceed c (regressions).
        self.assertGreater(overall.mcnemar["b"], overall.mcnemar["c"])

    def test_delta_fpr_ci_does_not_cross_zero(self) -> None:
        """ΔFPR for post − pre must be strictly negative — its 95% CI must
        sit entirely below zero, confirming F10's FP reduction is not a
        sampling artefact.
        """

        overall = next(p for p in self.report.paired if p.scope == "overall")
        delta = overall.delta_fpr
        self.assertLess(delta["point"], 0.0)
        self.assertLess(delta["ci_high"], 0.0)

    def test_per_stratum_decomposition_partitions_all_cases(self) -> None:
        """Sum of n_cases across strata must equal the total. The five
        canonical fp_source strata must all be present.
        """

        self.assertEqual(
            set(self.report.per_stratum.keys()),
            {"line_comment", "block_comment", "string_literal", "char_literal", "text_block"},
        )
        total = sum(s.n_cases for s in self.report.per_stratum.values())
        self.assertEqual(total, self.report.n_cases)

    def test_comment_strata_show_clean_f10_improvement_in_per_stratum(self) -> None:
        """For each comment stratum, post_f10 must have strictly fewer FPs
        than pre_f10 (the substantive claim of F10's design).
        """

        for stratum_name in ("line_comment", "block_comment"):
            with self.subTest(stratum=stratum_name):
                strat = self.report.per_stratum[stratum_name]
                self.assertLess(
                    strat.methods["post_f10"].fp,
                    strat.methods["pre_f10"].fp,
                    msg=(
                        f"{stratum_name}: pre_f10 FP = "
                        f"{strat.methods['pre_f10'].fp}, "
                        f"post_f10 FP = {strat.methods['post_f10'].fp}"
                    ),
                )


class FormatMarkdownTests(unittest.TestCase):
    def test_renders_table_header_and_methods(self) -> None:
        m = MethodMetrics(
            name="pre_f10",
            tp=1, fp=2, tn=3, fn=4,
            precision=0.5, recall=0.6, f1=0.55,
            bootstrap={"precision": {"ci_low": 0.4, "ci_high": 0.7},
                       "recall": {"ci_low": 0.5, "ci_high": 0.8},
                       "f1": {"ci_low": 0.45, "ci_high": 0.7}},
        )
        from codegraph.evaluation.lexical_noise_eval import (
            CaseRow,
            DetectionResult as DR,
            EvalReport,
        )
        row = CaseRow(
            case_id="L01",
            file_name="L01.java",
            fp_source="line_comment",
            expected="negative",
            target_violation_ids=("ISO-A.10-WEAK-HASH",),
            by_method={
                "pre_f10": DR("L01", "pre_f10", ("ISO-A.10-WEAK-HASH",), True),
                "post_f10": DR("L01", "post_f10", (), False),
                "semgrep": DR("L01", "semgrep", (), False),
            },
        )
        report = EvalReport(
            benchmark_id="test",
            n_cases=1,
            rows=(row,),
            metrics={"pre_f10": m, "post_f10": m, "semgrep": m},
        )
        out = format_markdown_summary(report)
        self.assertIn("Detection Summary", out)
        self.assertIn("pre_f10", out)
        self.assertIn("post_f10", out)
        self.assertIn("semgrep", out)
        self.assertIn("Per-case verdicts", out)
        self.assertIn("L01", out)


if __name__ == "__main__":
    unittest.main()
