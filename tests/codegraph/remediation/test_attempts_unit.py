"""Unit tests for remediation attempt loop and candidate retry logic."""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock

from codegraph.remediation.attempts import (
    ReplacementAttemptOutcome,
    confidence_gate_result,
    handle_missing_updated_source,
)


class TestAttemptsUnit(unittest.TestCase):
    def test_outcome_initial_state(self) -> None:
        outcome = ReplacementAttemptOutcome()
        self.assertIsNone(outcome.updated_content)
        self.assertEqual(outcome.attempt_errors, [])
        self.assertEqual(outcome.raw_capture_files, [])

    def test_handle_missing_updated_source_no_fix(self) -> None:
        service = MagicMock()
        service._build_no_fix_response.return_value = {"status": "NO_FIX"}
        service._build_confidence.return_value = {"score": 0.8, "band": "apply"}
        capability = MagicMock()
        capability.support_tier = "Full"
        outcome = ReplacementAttemptOutcome()
        span = MagicMock()

        result = handle_missing_updated_source(
            service=service,
            llm_output={"decision": "no_fix", "reason": "unsafe pattern"},
            outcome=outcome,
            violation_id="V1",
            context={"rule_id": "ISO-A.8-SQL-INJECTION"},
            capability=capability,
            target_method="com.acme.Repo.query()",
            raw_capture_dir=None,
            attempt_num=1,
            attempt_span=span,
        )
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result["status"], "NO_FIX")

    def test_confidence_gate_result(self) -> None:
        service = MagicMock()
        service._build_no_fix_response.return_value = {"status": "NO_FIX"}
        result = confidence_gate_result(
            service=service,
            violation_id="V1",
            context={"rule_id": "ISO-A.8-SQL-INJECTION"},
            confidence={"score": 0.3, "band": "manual"},
            attempt_errors=["schema_error"],
            attempt_num=1,
        )
        self.assertEqual(result["status"], "NO_FIX")
        self.assertEqual(result["confidence"]["band"], "manual")


if __name__ == "__main__":
    unittest.main()
