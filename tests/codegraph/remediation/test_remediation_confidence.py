import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from codegraph.ingestion.snapshots import create_source_snapshot_from_bytes, sha256_hex
from codegraph.remediation.confidence import ConfidenceFeatures, assess_remediation_confidence
from codegraph.remediation.service import RemediationService


class RemediationConfidenceTests(unittest.TestCase):
    def test_assess_confidence_assigns_apply_band_for_strong_signal(self):
        assessment = assess_remediation_confidence(
            ConfidenceFeatures(
                support_tier="full",
                decision="apply_edits",
                structured_valid=True,
                has_exact_method_source=True,
                has_graph_context=True,
                attempt_count=1,
            ),
            threshold_apply=0.75,
            threshold_review=0.5,
            temperature=1.0,
        )

        self.assertGreaterEqual(assessment.score, 0.75)
        self.assertEqual(assessment.band, "apply")

    def test_assess_confidence_assigns_abstain_band_for_no_fix(self):
        assessment = assess_remediation_confidence(
            ConfidenceFeatures(
                support_tier="manual",
                decision="no_fix",
                structured_valid=True,
                has_exact_method_source=False,
                has_graph_context=False,
                attempt_count=1,
            ),
            threshold_apply=0.75,
            threshold_review=0.5,
            temperature=1.0,
        )

        self.assertLess(assessment.score, 0.5)
        self.assertEqual(assessment.band, "abstain")

    def test_apply_fix_confidence_gate_blocks_live_apply(self):
        with TemporaryDirectory() as tmp:
            src_path = Path(tmp) / "Example.java"
            src_path.write_text("class Example { void hash() {} }\n", encoding="utf-8")
            source_bytes = src_path.read_bytes()
            snapshot = create_source_snapshot_from_bytes(
                workspace_root=tmp,
                source_path=src_path,
                source_bytes=source_bytes,
                method_selector="Example#hash()",
                expected_source_sha256=sha256_hex(source_bytes),
            )
            method_key = f"workspace@revision:Example.java#{snapshot.identity.source_key}"

            remediation = RemediationService(llm_client=lambda *_args, **_kwargs: "")
            remediation.get_violation_context = lambda *_args, **_kwargs: {  # type: ignore[method-assign]
                "violation": {"violation_id": "ISO-A.10-WEAK-HASH", "reason": "md5"},
                "method_key": method_key,
                "target_method": snapshot.identity.syntactic_signature,
                "file_path": src_path.as_posix(),
                "rule_id": "ISO-A.10-WEAK-HASH",
                "evidence": {
                    "source_code": snapshot.method_source,
                    "source_sha256": snapshot.file_sha256,
                    "graph_context": {},
                    "vector_context": [],
                },
                "catalog_entry": {"title": "Cryptography (Weak Hash)"},
                "baseline_violations": [],
                "exact_method_source": snapshot.method_source,
            }
            remediation._resolve_file_path = lambda *_args, **_kwargs: src_path  # type: ignore[method-assign]
            remediation.propose_method_edits = (  # type: ignore[method-assign]
                lambda *_args, **_kwargs: {
                    "decision": "apply_edits",
                    "replacement_method_lines": ["public void hash() { }"],
                    "replacement_method_code": "public void hash() { }",
                    "generation": {
                        "decision": "apply_edits",
                        "raw_response_valid": True,
                    },
                }
            )
            with patch("codegraph.remediation.service.settings.remediation_confidence_gate_enabled", True):
                with patch("codegraph.remediation.service.settings.remediation_confidence_threshold_apply", 0.99):
                    with patch("codegraph.remediation.service.settings.remediation_confidence_threshold_review", 0.5):
                        out = remediation.apply_fix(
                            "ISO-A.10-WEAK-HASH",
                            method_key=method_key,
                            file_path=src_path.as_posix(),
                            mode="apply",
                        )

            self.assertEqual(out.get("status"), "NO_FIX")
            self.assertIn("confidence gate", out.get("error", ""))
            self.assertIsInstance(out.get("confidence"), dict)
            self.assertNotEqual(out["confidence"].get("band"), "apply")
            self.assertEqual(src_path.read_bytes(), source_bytes)


if __name__ == "__main__":
    unittest.main()
