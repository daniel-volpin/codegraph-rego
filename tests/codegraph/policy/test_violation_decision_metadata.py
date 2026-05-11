"""Tests for decision_id and evaluated_at metadata on violation records.

Every violation must carry a unique decision id and a UTC ISO-8601
timestamp so that artifacts can be correlated back to the exact OPA
evaluation that produced them.
"""

from __future__ import annotations

import re
import unittest
from datetime import datetime, timezone

from codegraph.policy.runtime.opa import build_violation_response


_DECISION_ID_RE = re.compile(r"^[0-9a-f]{32}$")


def _minimal_bundle() -> dict:
    return {
        "target_method": "org.example.Foo.hash()",
        "file_path": "src/main/java/org/example/Foo.java",
        "source_code": "public byte[] hash(){ return MessageDigest.getInstance(\"MD5\").digest(); }",
        "start_line": 10,
        "end_line": 12,
        "graph_context": {},
        "vector_context": [],
        "analysis_flags": {},
        "helper_summaries": {},
    }


class TestViolationDecisionMetadata(unittest.TestCase):
    def test_violation_carries_decision_id_and_evaluated_at(self) -> None:
        violation = build_violation_response(
            {"violation_id": "ISO-A.10-WEAK-HASH", "reason": "MD5"},
            _minimal_bundle(),
            control_meta=None,
        )

        self.assertIn("decision_id", violation)
        self.assertIn("evaluated_at", violation)
        self.assertRegex(violation["decision_id"], _DECISION_ID_RE)
        # ISO-8601 with timezone parses cleanly and is in UTC.
        parsed = datetime.fromisoformat(violation["evaluated_at"])
        self.assertIsNotNone(parsed.tzinfo)
        self.assertEqual(parsed.utcoffset(), timezone.utc.utcoffset(parsed))

    def test_two_violations_get_distinct_decision_ids(self) -> None:
        v1 = build_violation_response(
            {"violation_id": "ISO-A.10-WEAK-HASH", "reason": "MD5"},
            _minimal_bundle(),
            control_meta=None,
        )
        v2 = build_violation_response(
            {"violation_id": "ISO-A.10-WEAK-HASH", "reason": "MD5"},
            _minimal_bundle(),
            control_meta=None,
        )

        self.assertNotEqual(v1["decision_id"], v2["decision_id"])

    def test_caller_can_pin_decision_id_and_evaluated_at(self) -> None:
        violation = build_violation_response(
            {"violation_id": "ISO-A.10-WEAK-HASH", "reason": "MD5"},
            _minimal_bundle(),
            control_meta=None,
            decision_id="deadbeef" * 4,
            evaluated_at="2026-03-22T16:43:09.823146+00:00",
        )

        self.assertEqual(violation["decision_id"], "deadbeef" * 4)
        self.assertEqual(violation["evaluated_at"], "2026-03-22T16:43:09.823146+00:00")


if __name__ == "__main__":
    unittest.main()
