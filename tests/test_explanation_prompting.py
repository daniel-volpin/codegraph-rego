import unittest

from codegraph.llm.explanation_prompting import (
    build_explanation_evidence,
    build_explanation_prompt,
    build_explanation_response_format,
)


class TestExplanationPrompting(unittest.TestCase):
    def setUp(self) -> None:
        self.violation = {
            "violation_id": "ISO-A.10-WEAK-HASH",
            "reason": "Weak hash usage detected",
            "severity": "high",
            "file_path": "src/Foo.java",
            "target_method": "org.example.Foo.hash()",
            "evidence": {
                "file_path": "src/Foo.java",
                "target_method": "org.example.Foo.hash()",
                "start_line": 10,
                "end_line": 18,
                "source_code": "public String hash(String input) {\n    return DigestUtils.md5Hex(input);\n}\n" * 40,
                "graph_context": {
                    "annotations": ["Transactional", "PostMapping", "Audited", "Validated", "Secured", "RolesAllowed"],
                    "calls": [
                        "DigestUtils.md5Hex",
                        "Logger.info",
                        "DigestUtils.md5Hex",
                        "Audit.log",
                    ],
                    "callers": ["org.example.Controller.doPost", "org.example.Controller.doPut"],
                    "uses_fields": [{"name": "hashService"}, {"name": "logger"}],
                },
                "vector_context": ["org.example.Bar.hash()", "org.example.Baz.hash()"],
                "analysis_flags": {"uses_md5_literal": True, "uses_weak_cipher": False},
            },
        }

    def test_build_explanation_evidence_lean_summarizes_graph_and_drops_vector_context(self) -> None:
        payload = build_explanation_evidence(
            self.violation,
            include_graph_context=True,
            evidence_mode="lean",
        )

        self.assertEqual(payload["evidence_mode"], "lean")
        self.assertEqual(payload["vector_context"], [])
        self.assertIn("[truncated]", payload["source_code"])
        self.assertEqual(payload["graph_context"]["calls_count"], 4)
        self.assertEqual(payload["graph_context"]["callers_count"], 2)
        self.assertEqual(payload["graph_context"]["uses_fields_count"], 2)
        self.assertEqual(len(payload["graph_context"]["annotations"]), 5)
        self.assertEqual(len(payload["graph_context"]["notable_calls"]), 3)
        self.assertEqual(payload["graph_context"]["analysis_flags"], {"uses_md5_literal": True})

    def test_build_explanation_evidence_full_preserves_vector_context(self) -> None:
        payload = build_explanation_evidence(
            self.violation,
            include_graph_context=True,
            evidence_mode="full",
        )

        self.assertEqual(payload["evidence_mode"], "full")
        self.assertEqual(payload["vector_context"], ["org.example.Bar.hash()", "org.example.Baz.hash()"])
        self.assertIn("calls", payload["graph_context"])

    def test_build_explanation_prompt_without_context_omits_graph_sections(self) -> None:
        messages = build_explanation_prompt(
            self.violation,
            include_graph_context=False,
            evidence_mode="lean",
        )

        self.assertEqual(len(messages), 2)
        self.assertIn("Only the violation metadata is provided", messages[1]["content"])
        self.assertNotIn("Graph evidence summary", messages[1]["content"])
        self.assertNotIn("Similar methods (FAISS)", messages[1]["content"])

    def test_build_explanation_prompt_enforces_final_answer_only(self) -> None:
        messages = build_explanation_prompt(
            self.violation,
            include_graph_context=True,
            evidence_mode="lean",
        )

        self.assertIn("Do not include thinking process", messages[0]["content"])
        self.assertIn("Use the exact citation strings from the evidence bundle.", messages[1]["content"])
        self.assertIn("Do not output Thinking Process", messages[1]["content"])

    def test_build_explanation_response_format_requires_citation_why_fix(self) -> None:
        response_format = build_explanation_response_format()

        schema = response_format["json_schema"]["schema"]
        self.assertEqual(response_format["type"], "json_schema")
        self.assertEqual(schema["required"], ["citation", "why", "fix"])
        self.assertFalse(schema["additionalProperties"])


if __name__ == "__main__":
    unittest.main()
