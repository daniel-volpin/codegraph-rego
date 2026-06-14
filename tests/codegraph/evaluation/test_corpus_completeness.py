"""Regression tests for the thesis-mode corpus-completeness guard (EVAL-F5).

A benchmark run must not silently report thesis metrics from an incomplete
checkout. ``validate_staged_corpus`` fails fast in thesis mode (and is a no-op
in exploratory mode), validating by stable testcase identifiers and counts.
"""

import unittest
from pathlib import Path

from codegraph.evaluation.benchmark import (
    IncompleteCorpusError,
    missing_staged_testcases,
    validate_staged_corpus,
)


class CorpusCompletenessTests(unittest.TestCase):
    def _staged(self, ids: list[str]) -> dict[str, Path]:
        return {tc: Path(f"/tmp/{tc}.java") for tc in ids}

    def test_complete_corpus_passes_in_thesis_mode(self) -> None:
        requested = ["BenchmarkTest00001", "BenchmarkTest00002"]
        staged = self._staged(requested)
        missing = validate_staged_corpus(requested, staged, require_complete=True)
        self.assertEqual(missing, [])

    def test_incomplete_corpus_raises_in_thesis_mode(self) -> None:
        requested = ["BenchmarkTest00001", "BenchmarkTest00002", "BenchmarkTest00003"]
        staged = self._staged(["BenchmarkTest00001"])
        with self.assertRaises(IncompleteCorpusError) as ctx:
            validate_staged_corpus(requested, staged, require_complete=True)
        msg = str(ctx.exception)
        # Error names the count and the stable identifiers, not just a denominator.
        self.assertIn("2 of 3", msg)
        self.assertIn("BenchmarkTest00002", msg)
        self.assertIn("BenchmarkTest00003", msg)

    def test_incomplete_corpus_is_non_fatal_in_exploratory_mode(self) -> None:
        requested = ["BenchmarkTest00001", "BenchmarkTest00002"]
        staged = self._staged(["BenchmarkTest00001"])
        missing = validate_staged_corpus(requested, staged, require_complete=False)
        self.assertEqual(missing, ["BenchmarkTest00002"])

    def test_missing_helper_is_sorted_and_set_based(self) -> None:
        requested = ["B3", "B1", "B2", "B1"]
        staged = self._staged(["B2"])
        self.assertEqual(missing_staged_testcases(requested, staged), ["B1", "B3"])


if __name__ == "__main__":
    unittest.main()
