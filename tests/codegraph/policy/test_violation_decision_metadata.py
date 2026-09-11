"""Tests for decision_id and evaluated_at metadata on violation records.

Every violation must carry a unique decision id and a UTC ISO-8601
timestamp so that artifacts can be correlated back to the exact OPA
evaluation that produced them.
"""

from __future__ import annotations

import re
import unittest
from datetime import UTC, datetime

from codegraph.policy.runtime.opa import build_violation_response

_DECISION_ID_RE = re.compile(r"^[0-9a-f]{32}$")


def _minimal_bundle() -> dict:
    return {
        "target_method": "org.example.Foo.hash()",
        "method_key": "workspace@revision:src/main/java/org/example/Foo.java#method:hash/0",
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
    def test_violation_preserves_captured_file_hash_for_remediation_freshness(self) -> None:
        bundle = _minimal_bundle()
        bundle["parser"] = {"source_sha256": "ab" * 32}
        violation = build_violation_response(
            {"violation_id": "ISO-A.10-WEAK-HASH"},
            bundle,
            control_meta=None,
        )

        self.assertEqual(violation["evidence"]["source_sha256"], "ab" * 32)

    def test_missing_raw_evidence_is_not_replaced_with_masked_policy_source(self) -> None:
        bundle = _minimal_bundle()
        bundle["source_code"] = "masked policy input, not captured original source"
        violation = build_violation_response(
            {"violation_id": "ISO-A.10-WEAK-HASH"},
            bundle,
            control_meta=None,
        )

        self.assertFalse(violation["snippet_available"])
        self.assertEqual(violation["evidence"]["source_code"], "")

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
        self.assertEqual(parsed.utcoffset(), UTC.utcoffset(parsed))

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

    def test_violation_carries_operational_method_key_and_display_target_method(self) -> None:
        violation = build_violation_response(
            {"violation_id": "ISO-A.10-WEAK-HASH", "reason": "MD5"},
            _minimal_bundle(),
            control_meta=None,
        )

        self.assertEqual(violation["method_key"], "workspace@revision:src/main/java/org/example/Foo.java#method:hash/0")
        self.assertEqual(violation["target_method"], "org.example.Foo.hash()")
        self.assertEqual(
            violation["evidence"]["method_key"], "workspace@revision:src/main/java/org/example/Foo.java#method:hash/0"
        )
        self.assertEqual(violation["evidence"]["target_method"], "org.example.Foo.hash()")


if __name__ == "__main__":
    unittest.main()
