"""Unit tests for confidence calibration, reliability bins, and metric calculations."""

from __future__ import annotations

import unittest

from codegraph.evaluation.calibration import (
    _safe_float,
    build_confidence_calibration,
    is_fully_verified,
    render_calibration_markdown,
)


class TestCalibrationUnit(unittest.TestCase):
    def test_safe_float(self) -> None:
        self.assertEqual(_safe_float(0.5), 0.5)
        self.assertEqual(_safe_float("0.85"), 0.85)
        self.assertIsNone(_safe_float(-0.1))
        self.assertIsNone(_safe_float(1.5))
        self.assertIsNone(_safe_float("invalid"))

    def test_is_fully_verified(self) -> None:
        self.assertTrue(is_fully_verified({"fully_verified": True}))
        self.assertFalse(is_fully_verified({"fully_verified": False}))
        self.assertTrue(is_fully_verified({"policy_fixed": True, "build_success": True}))
        self.assertFalse(is_fully_verified({"policy_fixed": True, "build_success": False}))
        self.assertFalse(is_fully_verified({"policy_fixed": False, "build_success": True}))

    def test_build_confidence_calibration(self) -> None:
        results = [
            {"case_id": "c1", "status": "OK", "confidence": {"score": 0.9, "band": "apply"}, "policy_fixed": True, "build_success": True},
            {"case_id": "c2", "status": "BUILD_ERROR", "confidence": {"score": 0.4, "band": "review"}, "policy_fixed": True, "build_success": False},
            {"case_id": "c3", "status": "NO_FIX", "confidence": {"score": 0.1, "band": "manual"}, "policy_fixed": False, "build_success": False},
        ]
        cal = build_confidence_calibration(results, bins=5)
        self.assertIsNotNone(cal)
        assert cal is not None
        self.assertEqual(cal["count"], 3)
        self.assertEqual(cal["positive_count"], 1)
        self.assertEqual(cal["negative_count"], 2)
        self.assertIn("populations", cal)
        self.assertIn("attempted_only", cal["populations"])
        self.assertIn("no_fix_only", cal["populations"])

        md = render_calibration_markdown(cal)
        self.assertIn("# Remediation Calibration", md)
        self.assertIn("Reliability Bins", md)


if __name__ == "__main__":
    unittest.main()
