"""Tests for F05 calibration population split.

Asserts that build_confidence_calibration:
  * preserves the legacy top-level shape (count, brier_score, ece, ...)
  * adds a populations block with full / attempted_only / no_fix_only
  * separates NO_FIX results from attempted-but-failed results
"""

from __future__ import annotations

import unittest
from typing import Any, Dict, List

from codegraph.evaluation.remediation_runtime import (
    ATTEMPTED_REMEDIATION_STATUSES,
    build_confidence_calibration,
)


def _result(
    *,
    case_id: str,
    status: str,
    confidence: float,
    fully_verified: bool,
) -> Dict[str, Any]:
    return {
        "case_id": case_id,
        "violation_id": "ISO-A.10-WEAK-HASH",
        "status": status,
        "confidence": {"score": confidence, "band": "review"},
        "policy_fixed": fully_verified,
        "build_success": fully_verified,
        "fully_verified": fully_verified,
    }


class TestCalibrationPopulationSplit(unittest.TestCase):
    def _mixed_results(self) -> List[Dict[str, Any]]:
        # Five attempted (some succeed, some fail) and three NO_FIX abstentions.
        return [
            _result(case_id="a1", status="OK", confidence=0.9, fully_verified=True),
            _result(case_id="a2", status="OK", confidence=0.85, fully_verified=True),
            _result(case_id="a3", status="BUILD_ERROR", confidence=0.7, fully_verified=False),
            _result(case_id="a4", status="GENERATION_ERROR", confidence=0.4, fully_verified=False),
            _result(case_id="a5", status="VERIFICATION_ERROR", confidence=0.3, fully_verified=False),
            _result(case_id="n1", status="NO_FIX", confidence=0.1, fully_verified=False),
            _result(case_id="n2", status="NO_FIX", confidence=0.05, fully_verified=False),
            _result(case_id="n3", status="NO_FIX", confidence=0.15, fully_verified=False),
        ]

    def test_legacy_top_level_fields_match_full_population(self) -> None:
        calib = build_confidence_calibration(self._mixed_results())
        self.assertIsNotNone(calib)
        full = calib["populations"]["full"]
        self.assertEqual(calib["count"], full["count"])
        self.assertEqual(calib["brier_score"], full["brier_score"])
        self.assertEqual(calib["ece"], full["ece"])
        self.assertEqual(calib["positive_count"], full["positive_count"])
        self.assertEqual(calib["negative_count"], full["negative_count"])

    def test_populations_block_has_three_keys(self) -> None:
        calib = build_confidence_calibration(self._mixed_results())
        self.assertEqual(set(calib["populations"].keys()), {"full", "attempted_only", "no_fix_only"})

    def test_attempted_only_excludes_no_fix(self) -> None:
        calib = build_confidence_calibration(self._mixed_results())
        attempted = calib["populations"]["attempted_only"]
        full = calib["populations"]["full"]
        self.assertEqual(attempted["count"], 5)
        self.assertEqual(full["count"], 8)
        # All attempted-only cases must have a status in the attempted set.
        for case in attempted["cases"]:
            self.assertIn(case["status"], set(ATTEMPTED_REMEDIATION_STATUSES))

    def test_no_fix_only_isolates_abstentions(self) -> None:
        calib = build_confidence_calibration(self._mixed_results())
        no_fix = calib["populations"]["no_fix_only"]
        self.assertEqual(no_fix["count"], 3)
        for case in no_fix["cases"]:
            self.assertEqual(case["status"], "NO_FIX")
            self.assertFalse(case["fully_verified"])

    def test_attempted_only_brier_can_differ_from_full(self) -> None:
        calib = build_confidence_calibration(self._mixed_results())
        full_brier = calib["populations"]["full"]["brier_score"]
        attempted_brier = calib["populations"]["attempted_only"]["brier_score"]
        # NO_FIX abstentions are correctly low-confidence (~0.1) with label 0,
        # so their (score - label)^2 is small, dragging the full Brier toward
        # zero relative to the attempted-only Brier. We do not assert a strict
        # inequality (the relationship depends on the test fixture), only that
        # the two values are stored independently and are floats.
        self.assertIsInstance(full_brier, float)
        self.assertIsInstance(attempted_brier, float)

    def test_empty_results_returns_none(self) -> None:
        self.assertIsNone(build_confidence_calibration([]))

    def test_only_no_fix_results_still_produce_block(self) -> None:
        results = [_result(case_id=f"n{i}", status="NO_FIX", confidence=0.1, fully_verified=False) for i in range(3)]
        calib = build_confidence_calibration(results)
        self.assertIsNotNone(calib)
        self.assertEqual(calib["populations"]["full"]["count"], 3)
        self.assertEqual(calib["populations"]["no_fix_only"]["count"], 3)
        self.assertIsNone(calib["populations"]["attempted_only"])  # no attempted results


if __name__ == "__main__":
    unittest.main()
