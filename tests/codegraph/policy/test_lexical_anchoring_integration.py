"""Integration: the bundle/violation pipeline correctly splits cleaned vs raw.

The Rego layer and the Python regex pre-analysis must see the
lexically-active view of the source (comments and string literals
stripped). The LLM-facing evidence card and the violation snippet
must continue to receive the raw source so citation grounding stays
human-readable.
"""

from __future__ import annotations

import unittest

from codegraph.policy.runtime.opa import build_violation_response
from codegraph.policy.source_analysis_core import strip_java_lexical_noise


class CleanedAndRawAreDistinctInBundle(unittest.TestCase):
    """The pipeline produces a bundle where ``source_code`` is cleaned and
    ``source_code_raw`` is the original — and build_violation_response
    routes them to the right consumer.
    """

    def test_violation_response_emits_raw_in_evidence_and_snippet(self) -> None:
        raw = '/* MD5 mention only in comment */\nint x = 1;\n'
        cleaned = strip_java_lexical_noise(raw)
        self.assertNotIn("MD5", cleaned)
        self.assertIn("MD5", raw)

        bundle = {
            "target_method": "Example.demo()",
            "file_path": "src/main/java/Example.java",
            "source_code": cleaned,
            "source_code_raw": raw,
            "start_line": 1,
            "end_line": 2,
            "graph_context": {},
            "vector_context": [],
            "analysis_flags": {},
            "helper_summaries": {},
        }
        violation = build_violation_response(
            {"violation_id": "ISO-A.10-WEAK-HASH", "reason": "MD5"},
            bundle,
            control_meta=None,
        )

        # Human-facing fields carry the raw text (MD5 visible in the
        # comment) so the LLM can ground its citation on what the
        # developer actually wrote.
        self.assertIn("MD5", violation["code_snippet"])
        self.assertIn("MD5", violation["evidence"]["source_code"])

    def test_violation_response_falls_back_when_raw_field_absent(self) -> None:
        """Bundles produced before the source_code_raw field existed must
        still work — the absence falls back to source_code.
        """
        legacy_bundle = {
            "target_method": "X.y()",
            "file_path": "X.java",
            "source_code": "int x = 1;",
            "start_line": 1,
            "end_line": 1,
            "graph_context": {},
            "vector_context": [],
            "analysis_flags": {},
            "helper_summaries": {},
        }
        violation = build_violation_response(
            {"violation_id": "ISO-A.8-SQL-INJECTION", "reason": "test"},
            legacy_bundle,
            control_meta=None,
        )
        self.assertEqual(violation["code_snippet"], "int x = 1;")
        self.assertEqual(violation["evidence"]["source_code"], "int x = 1;")


if __name__ == "__main__":
    unittest.main()
