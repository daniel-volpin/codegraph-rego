"""Tests for the shadow remediation comparison module."""

from __future__ import annotations

import json
import unittest
from typing import Any

from codegraph.remediation.comparison import (
    CandidateOutcome,
    ComparisonLabel,
    ComparisonResult,
    ComparisonSummary,
    build_comparison_summary,
    build_deterministic_outcome,
    build_llm_outcome,
    classify_comparison,
    compare_remediation,
    render_comparison_summary_markdown,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _det(produced: bool = False, refused: bool = False, error: str | None = None, edits: int = 0) -> CandidateOutcome:
    return CandidateOutcome(
        source="deterministic",
        produced_edits=produced,
        refused=refused,
        error=error,
        edit_count=edits,
    )


def _llm(produced: bool = False, refused: bool = False, error: str | None = None, edits: int = 0) -> CandidateOutcome:
    return CandidateOutcome(
        source="llm",
        produced_edits=produced,
        refused=refused,
        error=error,
        edit_count=edits,
    )


def _ctx(
    rule_id: str = "ISO-A.10-WEAK-HASH",
    violation_id: str = "v1",
    file_path: str = "Foo.java",
    target_method: str = "hash()",
    source_code: str = 'MessageDigest.getInstance("MD5")',
) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "violation_id": violation_id,
        "file_path": file_path,
        "target_method": target_method,
        "evidence": {"source_code": source_code},
    }


# ---------------------------------------------------------------------------
# Classification tests
# ---------------------------------------------------------------------------


class TestClassifyComparison(unittest.TestCase):
    """Test all branches of classify_comparison."""

    def test_both_produced_edits(self) -> None:
        label = classify_comparison(_det(produced=True), _llm(produced=True))
        self.assertEqual(label, ComparisonLabel.BOTH_PRODUCED_EDITS)

    def test_deterministic_only_llm_failed(self) -> None:
        label = classify_comparison(_det(produced=True), _llm(error="gen error"))
        self.assertEqual(label, ComparisonLabel.DETERMINISTIC_ONLY)

    def test_deterministic_only_llm_refused(self) -> None:
        label = classify_comparison(_det(produced=True), _llm(refused=True))
        self.assertEqual(label, ComparisonLabel.LLM_REFUSED_DETERMINISTIC_PRODUCED)

    def test_llm_only_det_failed(self) -> None:
        label = classify_comparison(_det(error="compile_error"), _llm(produced=True))
        self.assertEqual(label, ComparisonLabel.LLM_ONLY)

    def test_llm_only_det_refused(self) -> None:
        label = classify_comparison(_det(refused=True), _llm(produced=True))
        self.assertEqual(label, ComparisonLabel.DETERMINISTIC_REFUSED_LLM_PRODUCED)

    def test_both_refused(self) -> None:
        label = classify_comparison(_det(refused=True), _llm(refused=True))
        self.assertEqual(label, ComparisonLabel.BOTH_REFUSED)

    def test_both_failed(self) -> None:
        label = classify_comparison(
            _det(error="compile_error"),
            _llm(error="gen_error"),
        )
        self.assertEqual(label, ComparisonLabel.BOTH_FAILED)

    def test_det_refused_llm_failed(self) -> None:
        """det refused + llm failed (not refused) — neither produced, only det refused."""
        label = classify_comparison(_det(refused=True), _llm(error="x"))
        # llm is not refused, just errored; only det.refused is True.
        self.assertEqual(label, ComparisonLabel.BOTH_FAILED)

    def test_det_failed_llm_refused(self) -> None:
        """det failed + llm refused = both_failed (neither produced)."""
        label = classify_comparison(_det(error="x"), _llm(refused=True))
        self.assertEqual(label, ComparisonLabel.BOTH_FAILED)

    def test_all_labels_are_reachable(self) -> None:
        """Ensure all ComparisonLabel variants are covered by classification."""
        reachable = {
            classify_comparison(_det(produced=True), _llm(produced=True)),
            classify_comparison(_det(produced=True), _llm(error="x")),
            classify_comparison(_det(produced=True), _llm(refused=True)),
            classify_comparison(_det(error="x"), _llm(produced=True)),
            classify_comparison(_det(refused=True), _llm(produced=True)),
            classify_comparison(_det(refused=True), _llm(refused=True)),
            classify_comparison(_det(error="x"), _llm(error="x")),
        }
        self.assertEqual(reachable, set(ComparisonLabel))


# ---------------------------------------------------------------------------
# Deterministic outcome builder
# ---------------------------------------------------------------------------


class TestBuildDeterministicOutcome(unittest.TestCase):
    """Test build_deterministic_outcome with real planner + compiler."""

    def test_weak_hash_success(self) -> None:
        ctx = _ctx(source_code='MessageDigest.getInstance("MD5")')
        source = [
            "public byte[] hash(byte[] data) throws Exception {",
            '    MessageDigest md = MessageDigest.getInstance("MD5");',
            "    return md.digest(data);",
            "}",
        ]
        outcome = build_deterministic_outcome(ctx, source)
        self.assertEqual(outcome.source, "deterministic")
        self.assertTrue(outcome.produced_edits)
        self.assertFalse(outcome.refused)
        self.assertIsNone(outcome.error)
        self.assertGreater(outcome.edit_count, 0)
        self.assertIsNotNone(outcome.diff_snippet)

    def test_unsupported_rule_refused(self) -> None:
        ctx = _ctx(rule_id="ISO-A.8-SQL-INJECTION")
        outcome = build_deterministic_outcome(ctx, ["public void x() {}"])
        self.assertFalse(outcome.produced_edits)
        self.assertTrue(outcome.refused)

    def test_weak_random_unsupported_pattern_refused(self) -> None:
        ctx = _ctx(rule_id="ISO-A.10-WEAK-RANDOM", source_code="no random usage")
        outcome = build_deterministic_outcome(ctx, ["public void x() {}"])
        self.assertFalse(outcome.produced_edits)
        self.assertTrue(outcome.refused)

    def test_compile_error_recorded(self) -> None:
        """Supported rule but source doesn't contain the target literal."""
        ctx = _ctx(
            rule_id="ISO-A.10-WEAK-HASH",
            source_code='MessageDigest.getInstance("MD5")',
        )
        # Source lines that don't contain MD5 → compiler will error.
        source = [
            "public void safe() {",
            '    MessageDigest.getInstance("SHA-256");',
            "}",
        ]
        outcome = build_deterministic_outcome(ctx, source)
        self.assertFalse(outcome.produced_edits)
        self.assertFalse(outcome.refused)
        self.assertIsNotNone(outcome.error)
        self.assertIn("compile_error", outcome.error)


# ---------------------------------------------------------------------------
# LLM outcome builder
# ---------------------------------------------------------------------------


class TestBuildLlmOutcome(unittest.TestCase):
    """Test build_llm_outcome with various apply_result shapes."""

    def test_successful_llm_result(self) -> None:
        apply_result: dict[str, Any] = {
            "status": "OK",
            "updated_source_code": "updated code",
            "diff": "--- a\n+++ b\n-old\n+new",
            "generation": {
                "decision": "apply_edits",
                "edits": [{"start_line": 1, "end_line": 1, "original_lines": ["a"], "replacement_lines": ["b"]}],
                "raw_response_valid": True,
            },
        }
        outcome = build_llm_outcome(apply_result)
        self.assertEqual(outcome.source, "llm")
        self.assertTrue(outcome.produced_edits)
        self.assertFalse(outcome.refused)
        self.assertEqual(outcome.edit_count, 1)
        self.assertIsNotNone(outcome.diff_snippet)

    def test_no_fix_result(self) -> None:
        apply_result: dict[str, Any] = {
            "status": "NO_FIX",
            "error": "NO_FIX: unsupported",
            "generation": {"decision": "no_fix", "edits": []},
        }
        outcome = build_llm_outcome(apply_result)
        self.assertFalse(outcome.produced_edits)
        self.assertTrue(outcome.refused)

    def test_generation_error_result(self) -> None:
        apply_result: dict[str, Any] = {
            "status": "GENERATION_ERROR",
            "error": "parse failure",
            "generation": None,
        }
        outcome = build_llm_outcome(apply_result)
        self.assertFalse(outcome.produced_edits)
        self.assertFalse(outcome.refused)
        self.assertIsNotNone(outcome.error)

    def test_empty_result(self) -> None:
        outcome = build_llm_outcome({})
        self.assertFalse(outcome.produced_edits)
        self.assertFalse(outcome.refused)


# ---------------------------------------------------------------------------
# Compare remediation
# ---------------------------------------------------------------------------


class TestCompareRemediation(unittest.TestCase):
    """Test the compare_remediation function."""

    def test_produces_comparison_result(self) -> None:
        ctx = _ctx()
        det = _det(produced=True, edits=1)
        llm = _llm(produced=True, edits=2)
        result = compare_remediation(ctx, det, llm)
        self.assertIsInstance(result, ComparisonResult)
        self.assertEqual(result.violation_id, "v1")
        self.assertEqual(result.rule_id, "ISO-A.10-WEAK-HASH")
        self.assertEqual(result.label, ComparisonLabel.BOTH_PRODUCED_EDITS)

    def test_round_trip_serialization(self) -> None:
        ctx = _ctx()
        result = compare_remediation(ctx, _det(produced=True, edits=1), _llm(refused=True))
        dumped = result.model_dump()
        restored = ComparisonResult.model_validate(dumped)
        self.assertEqual(restored, result)
        json_str = result.model_dump_json()
        restored_json = ComparisonResult.model_validate_json(json_str)
        self.assertEqual(restored_json, result)


# ---------------------------------------------------------------------------
# Aggregate summary
# ---------------------------------------------------------------------------


class TestBuildComparisonSummary(unittest.TestCase):
    """Test aggregate summary building."""

    def test_empty_results(self) -> None:
        summary = build_comparison_summary([])
        self.assertEqual(summary.total_cases, 0)
        self.assertEqual(sum(summary.label_counts.values()), 0)

    def test_counts_by_label(self) -> None:
        results = [
            ComparisonResult(
                violation_id="v1",
                rule_id="ISO-A.10-WEAK-HASH",
                file_path="a.java",
                target_method="a()",
                label=ComparisonLabel.BOTH_PRODUCED_EDITS,
                deterministic=_det(produced=True),
                llm=_llm(produced=True),
            ),
            ComparisonResult(
                violation_id="v2",
                rule_id="ISO-A.10-WEAK-HASH",
                file_path="b.java",
                target_method="b()",
                label=ComparisonLabel.BOTH_PRODUCED_EDITS,
                deterministic=_det(produced=True),
                llm=_llm(produced=True),
            ),
            ComparisonResult(
                violation_id="v3",
                rule_id="ISO-A.10-WEAK-RANDOM",
                file_path="c.java",
                target_method="c()",
                label=ComparisonLabel.DETERMINISTIC_ONLY,
                deterministic=_det(produced=True),
                llm=_llm(error="x"),
            ),
        ]
        summary = build_comparison_summary(results)
        self.assertEqual(summary.total_cases, 3)
        self.assertEqual(summary.label_counts["both_produced_edits"], 2)
        self.assertEqual(summary.label_counts["deterministic_only"], 1)

    def test_per_rule_breakdown(self) -> None:
        results = [
            ComparisonResult(
                violation_id="v1",
                rule_id="ISO-A.10-WEAK-HASH",
                file_path="a.java",
                target_method="a()",
                label=ComparisonLabel.BOTH_PRODUCED_EDITS,
                deterministic=_det(produced=True),
                llm=_llm(produced=True),
            ),
            ComparisonResult(
                violation_id="v2",
                rule_id="ISO-A.10-WEAK-RANDOM",
                file_path="b.java",
                target_method="b()",
                label=ComparisonLabel.LLM_ONLY,
                deterministic=_det(error="x"),
                llm=_llm(produced=True),
            ),
        ]
        summary = build_comparison_summary(results)
        self.assertIn("ISO-A.10-WEAK-HASH", summary.per_rule)
        self.assertIn("ISO-A.10-WEAK-RANDOM", summary.per_rule)
        self.assertEqual(summary.per_rule["ISO-A.10-WEAK-HASH"]["both_produced_edits"], 1)
        self.assertEqual(summary.per_rule["ISO-A.10-WEAK-RANDOM"]["llm_only"], 1)

    def test_summary_round_trip(self) -> None:
        summary = ComparisonSummary(
            total_cases=5,
            label_counts={"both_produced_edits": 3, "llm_only": 2},
            per_rule={"ISO-A.10-WEAK-HASH": {"both_produced_edits": 3}},
        )
        dumped = summary.model_dump()
        restored = ComparisonSummary.model_validate(dumped)
        self.assertEqual(restored, summary)
        json_str = json.dumps(dumped)
        restored_json = ComparisonSummary.model_validate(json.loads(json_str))
        self.assertEqual(restored_json, summary)


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------


class TestRenderMarkdown(unittest.TestCase):
    """Test markdown summary rendering."""

    def test_renders_without_error(self) -> None:
        summary = ComparisonSummary(
            total_cases=3,
            label_counts={"both_produced_edits": 2, "deterministic_only": 1},
            per_rule={"ISO-A.10-WEAK-HASH": {"both_produced_edits": 2}},
        )
        md = render_comparison_summary_markdown(summary)
        self.assertIn("Remediation Comparison Summary", md)
        self.assertIn("both_produced_edits", md)
        self.assertIn("ISO-A.10-WEAK-HASH", md)

    def test_renders_empty_summary(self) -> None:
        summary = ComparisonSummary(total_cases=0)
        md = render_comparison_summary_markdown(summary)
        self.assertIn("Total cases:** 0", md)


if __name__ == "__main__":
    unittest.main()
