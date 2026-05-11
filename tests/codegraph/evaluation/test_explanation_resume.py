"""Tests for the F21 resume helper in codegraph.evaluation.explanation_runtime.

The resume contract:
  * ``load_completed_violation_outcomes`` returns
    ``{(cohort, category_id, violation_id): {with_context_hit, without_context_hit}}``
    only for entries where BOTH context modes are present.
  * Partial pairs (one mode missing) are omitted so the eval re-runs them.
  * Legacy rows (no ``cohort`` field) are treated as TP cohort.
  * Malformed JSON lines and rows lacking required fields are skipped.
  * ``ExplanationRuntime(resume=True)`` opens artifact files in append mode.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from codegraph.evaluation.explanation_runtime import (
    ExplanationRuntime,
    load_completed_violation_outcomes,
)


def _row(
    *,
    cohort: str | None,
    category_id: str,
    violation_id: str,
    context_mode: str,
    citation_hit: bool,
) -> dict:
    row = {
        "category_id": category_id,
        "violation_id": violation_id,
        "context_mode": context_mode,
        "citation_hit": citation_hit,
    }
    if cohort is not None:
        row["cohort"] = cohort
    return row


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row) + "\n")


class LoadCompletedViolationOutcomesTests(unittest.TestCase):
    def test_missing_file_returns_empty_map(self) -> None:
        with TemporaryDirectory() as tmp:
            outcomes = load_completed_violation_outcomes(Path(tmp) / "missing.jsonl")
        self.assertEqual(outcomes, {})

    def test_complete_pair_is_recovered(self) -> None:
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "request_metrics.jsonl"
            _write_jsonl(
                path,
                [
                    _row(cohort="tp", category_id="sql", violation_id="v1", context_mode="with_context", citation_hit=True),
                    _row(cohort="tp", category_id="sql", violation_id="v1", context_mode="without_context", citation_hit=False),
                ],
            )
            outcomes = load_completed_violation_outcomes(path)
        key = ("tp", "sql", "v1")
        self.assertIn(key, outcomes)
        self.assertEqual(outcomes[key], {"with_context_hit": True, "without_context_hit": False})

    def test_partial_pair_is_excluded(self) -> None:
        """A violation with only with_context (no without_context) must be redone."""
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "request_metrics.jsonl"
            _write_jsonl(
                path,
                [
                    _row(cohort="tp", category_id="sql", violation_id="v1", context_mode="with_context", citation_hit=True),
                    # without_context row missing -> incomplete pair
                ],
            )
            outcomes = load_completed_violation_outcomes(path)
        self.assertEqual(outcomes, {})

    def test_legacy_rows_without_cohort_default_to_tp(self) -> None:
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "request_metrics.jsonl"
            _write_jsonl(
                path,
                [
                    _row(cohort=None, category_id="cmd", violation_id="v2", context_mode="with_context", citation_hit=True),
                    _row(cohort=None, category_id="cmd", violation_id="v2", context_mode="without_context", citation_hit=True),
                ],
            )
            outcomes = load_completed_violation_outcomes(path)
        self.assertIn(("tp", "cmd", "v2"), outcomes)

    def test_malformed_and_partial_rows_are_skipped(self) -> None:
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "request_metrics.jsonl"
            with path.open("w", encoding="utf-8") as handle:
                handle.write("not a json line\n")
                handle.write(json.dumps({"category_id": "sql"}) + "\n")  # missing violation_id
                handle.write("\n")  # blank
                handle.write(
                    json.dumps(
                        _row(
                            cohort="fp",
                            category_id="sql",
                            violation_id="v3",
                            context_mode="with_context",
                            citation_hit=False,
                        )
                    )
                    + "\n"
                )
                handle.write(
                    json.dumps(
                        _row(
                            cohort="fp",
                            category_id="sql",
                            violation_id="v3",
                            context_mode="without_context",
                            citation_hit=False,
                        )
                    )
                    + "\n"
                )
            outcomes = load_completed_violation_outcomes(path)
        # Only the well-formed FP pair survives.
        self.assertEqual(set(outcomes.keys()), {("fp", "sql", "v3")})

    def test_tp_and_fp_cohorts_are_separate_keys(self) -> None:
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "request_metrics.jsonl"
            _write_jsonl(
                path,
                [
                    _row(cohort="tp", category_id="hash", violation_id="v4", context_mode="with_context", citation_hit=True),
                    _row(cohort="tp", category_id="hash", violation_id="v4", context_mode="without_context", citation_hit=False),
                    _row(cohort="fp", category_id="hash", violation_id="v4", context_mode="with_context", citation_hit=False),
                    _row(cohort="fp", category_id="hash", violation_id="v4", context_mode="without_context", citation_hit=False),
                ],
            )
            outcomes = load_completed_violation_outcomes(path)
        self.assertIn(("tp", "hash", "v4"), outcomes)
        self.assertIn(("fp", "hash", "v4"), outcomes)
        # And they hold independent hit values.
        self.assertTrue(outcomes[("tp", "hash", "v4")]["with_context_hit"])
        self.assertFalse(outcomes[("fp", "hash", "v4")]["with_context_hit"])


class ExplanationRuntimeResumeFileModeTests(unittest.TestCase):
    def _make_runtime(self, output_dir: Path, *, resume: bool) -> ExplanationRuntime:
        return ExplanationRuntime(
            output_dir=output_dir,
            benchmark_root=output_dir,
            truth_path=output_dir / "truth.csv",
            truth_schema={},
            selection_cfg={},
            coverage_by_category={},
            sample_per_category=3,
            resume=resume,
        )

    def test_default_truncates_existing_artifact_files(self) -> None:
        with TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            (output_dir / "request_metrics.jsonl").write_text("old line\n", encoding="utf-8")
            (output_dir / "explanation_samples.jsonl").write_text("old sample\n", encoding="utf-8")

            runtime = self._make_runtime(output_dir, resume=False)
            try:
                runtime.write_request_metric({"hello": "new"})
                runtime.write_sample({"hello": "sample"})
            finally:
                runtime.close()

            self.assertNotIn("old line", (output_dir / "request_metrics.jsonl").read_text())
            self.assertIn('"hello": "new"', (output_dir / "request_metrics.jsonl").read_text())
            self.assertNotIn("old sample", (output_dir / "explanation_samples.jsonl").read_text())

    def test_resume_appends_to_existing_artifact_files(self) -> None:
        with TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            (output_dir / "request_metrics.jsonl").write_text(
                '{"category_id": "sql", "violation_id": "v1"}\n',
                encoding="utf-8",
            )
            (output_dir / "explanation_samples.jsonl").write_text('{"prior": true}\n', encoding="utf-8")

            runtime = self._make_runtime(output_dir, resume=True)
            try:
                runtime.write_request_metric({"hello": "appended"})
                runtime.write_sample({"hello": "sample"})
            finally:
                runtime.close()

            metrics_text = (output_dir / "request_metrics.jsonl").read_text()
            samples_text = (output_dir / "explanation_samples.jsonl").read_text()
            self.assertIn("v1", metrics_text)
            self.assertIn("appended", metrics_text)
            self.assertIn("prior", samples_text)
            self.assertIn("sample", samples_text)


if __name__ == "__main__":
    unittest.main()
