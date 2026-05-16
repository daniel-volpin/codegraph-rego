"""Tests for the OWASP Benchmark file-level F10 eval."""

from __future__ import annotations

import csv
import shutil
import tempfile
import unittest
from pathlib import Path

from baselines.semgrep.runner import run_semgrep_baseline
from codegraph.evaluation.owasp_lexical_eval import (
    CWE_TO_ISO,
    SUPPORTED_CWES,
    OwaspCase,
    _detect_via_semgrep_for_owasp,
    evaluate_owasp,
    format_markdown_summary,
    load_owasp_cases,
    owasp_corpus_sha,
    owasp_paths,
    resolve_owasp_root,
)


PROJECT_ROOT = Path(__file__).resolve().parents[3]


def _opa_available() -> bool:
    return shutil.which("opa") is not None


def _semgrep_available() -> bool:
    if shutil.which("semgrep"):
        return True
    return (PROJECT_ROOT / ".venv" / "bin" / "semgrep").is_file()


class OwaspCorpusSHATests(unittest.TestCase):
    """Provenance: pin the OWASP checkout commit SHA when available."""

    def test_returns_none_when_not_a_git_repo(self) -> None:
        tmp = tempfile.mkdtemp()
        try:
            self.assertIsNone(owasp_corpus_sha(Path(tmp)))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_returns_hex_sha_when_present(self) -> None:
        # /tmp/owasp-benchmark is git-cloned in the dev shell; if it
        # exists, the SHA must be a 40-char hex string. Skip otherwise.
        candidate = Path("/tmp/owasp-benchmark")
        if not (candidate / ".git").is_dir():
            self.skipTest("/tmp/owasp-benchmark is not a git repo")
        sha = owasp_corpus_sha(candidate)
        self.assertIsNotNone(sha)
        self.assertEqual(len(sha), 40)
        self.assertTrue(all(c in "0123456789abcdef" for c in sha))


class CWEMappingTests(unittest.TestCase):
    def test_eight_cwes_supported(self) -> None:
        self.assertEqual(len(SUPPORTED_CWES), 8)

    def test_every_supported_cwe_maps_to_iso_violation(self) -> None:
        for cwe in SUPPORTED_CWES:
            with self.subTest(cwe=cwe):
                self.assertIn(cwe, CWE_TO_ISO)
                self.assertTrue(CWE_TO_ISO[cwe].startswith("ISO-A."))

    def test_no_extra_iso_keys(self) -> None:
        self.assertEqual(set(CWE_TO_ISO.keys()), SUPPORTED_CWES)


class LoaderTests(unittest.TestCase):
    """Loader is exercised against a synthetic in-memory CSV — independent of
    a real OWASP checkout."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp()
        self.java_root = Path(self.tmpdir) / "testcode"
        self.java_root.mkdir(parents=True)
        # synthesise a tiny manifest of 4 cases across 2 CWEs (+ one
        # unsupported CWE that must be filtered out).
        rows = [
            ["# header"],
            ["BenchmarkTest00001", "pathtraver", "true", "22"],
            ["BenchmarkTest00002", "pathtraver", "false", "22"],
            ["BenchmarkTest00003", "hash", "true", "328"],
            ["BenchmarkTest00004", "hash", "false", "328"],
            ["BenchmarkTest00005", "trustbound", "true", "501"],  # unsupported CWE
        ]
        self.csv_path = Path(self.tmpdir) / "expected.csv"
        with self.csv_path.open("w", encoding="utf-8", newline="") as f:
            csv.writer(f).writerows(rows)
        for name in (
            "BenchmarkTest00001",
            "BenchmarkTest00002",
            "BenchmarkTest00003",
            "BenchmarkTest00004",
        ):
            (self.java_root / f"{name}.java").write_text(
                "package x;\npublic class C{ public byte[] f(){return new byte[0];}}\n",
                encoding="utf-8",
            )

    def tearDown(self) -> None:
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_loads_only_supported_cwes(self) -> None:
        cases = load_owasp_cases(self.csv_path, self.java_root)
        cwes = {c.cwe for c in cases}
        self.assertNotIn("501", cwes, "unsupported CWE must be filtered out")
        self.assertEqual(cwes, {"22", "328"})

    def test_load_skips_missing_files(self) -> None:
        # Remove one source file so the loader must skip it.
        (self.java_root / "BenchmarkTest00002.java").unlink()
        cases = load_owasp_cases(self.csv_path, self.java_root)
        names = {c.test_name for c in cases}
        self.assertNotIn("BenchmarkTest00002", names)

    def test_limit_per_cwe_caps_evenly(self) -> None:
        cases = load_owasp_cases(self.csv_path, self.java_root, limit_per_cwe=1, seed=0)
        from collections import Counter
        counts = Counter(c.cwe for c in cases)
        self.assertEqual(counts["22"], 1)
        self.assertEqual(counts["328"], 1)

    def test_seed_deterministic(self) -> None:
        a = load_owasp_cases(self.csv_path, self.java_root, limit_per_cwe=1, seed=42)
        b = load_owasp_cases(self.csv_path, self.java_root, limit_per_cwe=1, seed=42)
        self.assertEqual([c.test_name for c in a], [c.test_name for c in b])

    def test_unsupported_cwe_filter_raises(self) -> None:
        with self.assertRaises(ValueError):
            load_owasp_cases(self.csv_path, self.java_root, cwes=["999"])


class SemgrepIndexingTests(unittest.TestCase):
    def test_resolves_per_case_target_fired(self) -> None:
        case = OwaspCase(
            test_name="BenchmarkTest42",
            category="pathtraver",
            real_vulnerability=True,
            cwe="22",
            java_path=Path("/tmp/BenchmarkTest42.java"),
        )
        idx = {"BenchmarkTest42.java": ["ISO-A.8-PATH-TRAVERSAL"]}
        result = _detect_via_semgrep_for_owasp(case, idx)
        self.assertTrue(result.target_fired)
        self.assertEqual(result.fired_violation_ids, ("ISO-A.8-PATH-TRAVERSAL",))

    def test_no_finding_when_filename_absent(self) -> None:
        case = OwaspCase(
            test_name="BenchmarkTest42",
            category="pathtraver",
            real_vulnerability=False,
            cwe="22",
            java_path=Path("/tmp/BenchmarkTest42.java"),
        )
        result = _detect_via_semgrep_for_owasp(case, {})
        self.assertFalse(result.target_fired)
        self.assertEqual(result.fired_violation_ids, ())


@unittest.skipUnless(_opa_available(), "opa CLI not installed")
@unittest.skipUnless(_semgrep_available(), "semgrep CLI not installed")
@unittest.skipUnless(resolve_owasp_root() is not None, "OWASP Benchmark not on disk")
class OwaspIntegrationTests(unittest.TestCase):
    """End-to-end on a stratified subset of the OWASP Benchmark.

    Pins F10's two structural properties on the OWASP synthetic corpus:
      (a) F10 does not regress detection (pre_f10 metrics == post_f10),
      (b) the SemGrep baseline produces zero FPs on the synthetic corpus
          (precision = 1.0).
    """

    LIMIT_PER_CWE = 10  # 80 cases total — keeps test runtime tight

    @classmethod
    def setUpClass(cls) -> None:
        owasp_root = resolve_owasp_root()
        assert owasp_root is not None  # guarded by skip
        csv_path, java_root = owasp_paths(owasp_root)
        cls.cases = load_owasp_cases(
            csv_path, java_root, limit_per_cwe=cls.LIMIT_PER_CWE, seed=0
        )
        cls.semgrep = run_semgrep_baseline(target=java_root)
        cls.report = evaluate_owasp(
            cls.cases,
            java_root=java_root,
            semgrep_result=cls.semgrep,
            n_resamples=100,
            seed=0,
        )

    def test_at_least_one_case_per_supported_cwe(self) -> None:
        loaded_cwes = {c.cwe for c in self.cases}
        self.assertEqual(loaded_cwes, SUPPORTED_CWES)

    def test_f10_does_not_change_owasp_outcomes(self) -> None:
        """Pre-F10 and post-F10 must agree on every OWASP case.

        OWASP test cases are mechanically generated and lack the
        comment / literal lexical-noise FP class that F10 targets.
        Any disagreement here would indicate F10 is over-stripping
        active code.
        """

        for row in self.report.rows:
            with self.subTest(test_name=row.case.test_name):
                self.assertEqual(
                    row.by_method["pre_f10"].target_fired,
                    row.by_method["post_f10"].target_fired,
                    msg=(
                        f"{row.case.test_name} (CWE-{row.case.cwe}) differs: "
                        f"pre_f10={row.by_method['pre_f10'].target_fired} "
                        f"post_f10={row.by_method['post_f10'].target_fired} "
                        "— F10 must be a no-op on the synthetic OWASP corpus"
                    ),
                )

    def test_pre_and_post_metrics_are_identical(self) -> None:
        pre = self.report.overall["pre_f10"]
        post = self.report.overall["post_f10"]
        self.assertEqual((pre.tp, pre.fp, pre.tn, pre.fn), (post.tp, post.fp, post.tn, post.fn))

    def test_semgrep_baseline_has_perfect_precision_on_owasp(self) -> None:
        sm = self.report.overall["semgrep"]
        if sm.tp + sm.fp > 0:
            self.assertEqual(
                sm.precision, 1.0,
                msg=f"SemGrep precision degraded to {sm.precision} on OWASP subset",
            )

    def test_owasp_mcnemar_undefined_across_every_scope(self) -> None:
        """OWASP regression-safety: F10 must produce zero disagreements
        on every scope (overall, fp_class, and each CWE). McNemar's
        test is therefore undefined — that is the *expected* statistical
        outcome for the synthetic-vs-real-gap claim.
        """

        for pc in self.report.paired:
            with self.subTest(scope=pc.scope):
                self.assertFalse(
                    pc.mcnemar["test_defined"],
                    msg=(
                        f"OWASP scope={pc.scope}: McNemar should be undefined "
                        f"(b=c=0) but got b={pc.mcnemar['b']} c={pc.mcnemar['c']}"
                    ),
                )
                self.assertEqual(pc.mcnemar["b"], 0)
                self.assertEqual(pc.mcnemar["c"], 0)

    def test_owasp_delta_rates_are_zero_with_zero_width_ci(self) -> None:
        """ΔFPR and ΔFNR must both be exactly 0.0 with zero-width CIs on
        OWASP — same regression-safety guarantee, restated as effect size.
        """

        for pc in self.report.paired:
            with self.subTest(scope=pc.scope):
                self.assertEqual(pc.delta_fpr["point"], 0.0)
                self.assertEqual(pc.delta_fpr["ci_low"], 0.0)
                self.assertEqual(pc.delta_fpr["ci_high"], 0.0)
                self.assertEqual(pc.delta_fnr["point"], 0.0)


class FormatMarkdownTests(unittest.TestCase):
    def test_markdown_contains_overall_and_per_cwe_sections(self) -> None:
        from codegraph.evaluation.lexical_noise_eval import (
            DetectionResult,
            MethodMetrics,
        )
        from codegraph.evaluation.owasp_lexical_eval import (
            OwaspCaseRow,
            OwaspEvalReport,
        )

        case = OwaspCase(
            test_name="BenchmarkTest00001",
            category="pathtraver",
            real_vulnerability=True,
            cwe="22",
            java_path=Path("/tmp/x.java"),
        )
        row = OwaspCaseRow(
            case=case,
            by_method={
                "pre_f10": DetectionResult(case.test_name, "pre_f10", (), False),
                "post_f10": DetectionResult(case.test_name, "post_f10", (), False),
                "semgrep": DetectionResult(case.test_name, "semgrep", (), False),
            },
        )
        empty_metrics = MethodMetrics(
            name="x", tp=0, fp=0, tn=0, fn=0, precision=0, recall=0, f1=0, bootstrap={}
        )
        report = OwaspEvalReport(
            benchmark_id="test",
            n_cases=1,
            cwes_evaluated=("22",),
            rows=(row,),
            overall={"pre_f10": empty_metrics, "post_f10": empty_metrics, "semgrep": empty_metrics},
            per_cwe={"22": {"pre_f10": empty_metrics, "post_f10": empty_metrics, "semgrep": empty_metrics}},
        )
        out = format_markdown_summary(report)
        self.assertIn("OWASP Benchmark v1.2", out)
        self.assertIn("## Overall metrics", out)
        self.assertIn("## Per-CWE metrics", out)
        self.assertIn("CWE-22", out)
        self.assertIn("ISO-A.8-PATH-TRAVERSAL", out)


if __name__ == "__main__":
    unittest.main()
