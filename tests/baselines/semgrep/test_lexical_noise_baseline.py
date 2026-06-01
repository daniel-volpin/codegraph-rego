"""Integration test: run SemGrep on the 30 LexicalNoiseJava fixtures.

Each NEG case in the manifest must produce *no* finding from the
SemGrep rule that mirrors its target violation. Each POS case must
produce exactly one matching finding. This pins the comparative
baseline used in the F10 thesis chapter: F10 brings the cheap lexical
Rego pipeline up to the FP resistance of AST-based SemGrep on this
synthetic FP class.

The test is skipped when the ``semgrep`` CLI is not on PATH, so
contributors without it can still run the rest of the suite.
"""

from __future__ import annotations

import shutil
import unittest
from pathlib import Path

from baselines.semgrep.runner import (
    DEFAULT_RULES_DIR,
    SemgrepNotInstalledError,
    run_semgrep_baseline,
)
from codegraph.evaluation.lexical_noise import load_lexical_noise_manifest

PROJECT_ROOT = Path(__file__).resolve().parents[3]
MANIFEST_PATH = PROJECT_ROOT / "configs" / "benchmark" / "lexical_noise_v1.json"


def _semgrep_available() -> bool:
    if shutil.which("semgrep"):
        return True
    venv_bin = PROJECT_ROOT / ".venv" / "bin" / "semgrep"
    return venv_bin.is_file()


@unittest.skipUnless(_semgrep_available(), "semgrep CLI not installed")
class SemgrepBaselineOnLexicalNoiseTests(unittest.TestCase):
    """End-to-end: SemGrep on the 30 LexicalNoiseJava fixtures."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.benchmark = load_lexical_noise_manifest(MANIFEST_PATH)
        fixture_root = cls.benchmark.resolve_fixture_root(PROJECT_ROOT)
        try:
            cls.result = run_semgrep_baseline(
                target=fixture_root,
                rules_dir=DEFAULT_RULES_DIR,
            )
        except SemgrepNotInstalledError as exc:  # pragma: no cover — guarded by skip
            raise unittest.SkipTest(str(exc))

    def test_thirty_fixtures_scanned(self) -> None:
        scanned = self.result.raw.get("paths", {}).get("scanned", [])
        self.assertEqual(len(scanned), 30, f"expected 30 fixtures scanned, got {len(scanned)}")

    def test_no_findings_on_any_negative_case(self) -> None:
        neg_filenames = {case.file_name for case in self.benchmark.negatives()}
        offending = [
            f for f in self.result.findings if Path(f.file_path).name in neg_filenames
        ]
        self.assertEqual(
            offending,
            [],
            msg=(
                "SemGrep AST baseline should not fire on any LexicalNoiseJava "
                f"negative fixture, but fired on: {[(f.file_path, f.rule_id) for f in offending]}"
            ),
        )

    def test_every_positive_case_has_at_least_one_finding(self) -> None:
        positives = self.benchmark.positives()
        by_file = self.result.findings_by_file()
        missing = []
        for case in positives:
            files_with_findings = [
                fp for fp in by_file if Path(fp).name == case.file_name
            ]
            if not files_with_findings:
                missing.append(case.case_id)
        self.assertEqual(
            missing,
            [],
            msg=f"SemGrep failed to flag POSITIVE fixtures: {missing}",
        )

    def test_positive_findings_use_the_expected_rule(self) -> None:
        positives = self.benchmark.positives()
        by_file = self.result.findings_by_file()
        for case in positives:
            with self.subTest(case_id=case.case_id):
                expected_cg_ids = set(case.target_violation_ids)
                fixture_findings = [
                    f
                    for path, fs in by_file.items()
                    if Path(path).name == case.file_name
                    for f in fs
                ]
                actual_cg_ids = {f.codegraph_violation_id for f in fixture_findings}
                self.assertTrue(
                    expected_cg_ids & actual_cg_ids,
                    msg=(
                        f"{case.case_id}: expected SemGrep to surface one of "
                        f"{expected_cg_ids}, got {actual_cg_ids}"
                    ),
                )

    def test_no_findings_outside_known_positives(self) -> None:
        pos_filenames = {case.file_name for case in self.benchmark.positives()}
        rogue = [
            f for f in self.result.findings if Path(f.file_path).name not in pos_filenames
        ]
        self.assertEqual(
            rogue,
            [],
            msg=f"SemGrep produced findings on non-positive files: {[(f.file_path, f.rule_id) for f in rogue]}",
        )


if __name__ == "__main__":
    unittest.main()
