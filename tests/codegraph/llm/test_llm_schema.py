import unittest

from codegraph.llm.schema.explanation import (
    parse_structured_explanation,
    parse_structured_explanation_strict,
)

try:
    import javalang  # noqa: F401
except ImportError:  # pragma: no cover - environment guard
    javalang = None


class TestLlmSchema(unittest.TestCase):
    def test_explanation_strict_rejects_preamble_but_salvage_accepts(self) -> None:
        raw = 'Thinking Process:\n1. Analyze\n{"citation":"src/Foo.java:10-18","why":"Weak hash is insecure.","fix":"Use SHA-256."}'

        strict = parse_structured_explanation_strict(raw)
        salvage = parse_structured_explanation(raw, allow_salvage=True)

        self.assertIsNone(strict)
        self.assertEqual(
            salvage,
            {
                "citation": "src/Foo.java:10-18",
                "why": "Weak hash is insecure.",
                "fix": "Use SHA-256.",
            },
        )

    def test_remediation_strict_rejects_preamble_but_salvage_accepts(self) -> None:
        from codegraph.llm.schema.remediation import (
            parse_structured_generation_response,
            parse_structured_generation_response_strict,
        )

        original = ['public void hash() { java.security.MessageDigest.getInstance("MD5"); }']
        raw = (
            'Analysis:\n'
            '{"decision":"apply_edits","edits":[{"start_line":1,"end_line":1,'
            '"original_lines":["public void hash() { java.security.MessageDigest.getInstance(\\"MD5\\"); }"],'
            '"replacement_lines":["public void hash() { java.security.MessageDigest.getInstance(\\"SHA-256\\"); }"]}],'
            '"reason":""}'
        )

        strict = parse_structured_generation_response_strict(
            raw,
            target_method="com.example.Foo.hash()",
            original_method_lines=original,
        )
        salvage = parse_structured_generation_response(
            raw,
            target_method="com.example.Foo.hash()",
            original_method_lines=original,
        )

        self.assertFalse(strict["raw_response_valid"])
        self.assertEqual(strict["schema_error"], "invalid_json: malformed remediation generation payload")
        self.assertTrue(salvage["raw_response_valid"])
        self.assertIn("SHA-256", salvage["replacement_method_code"])
    test_remediation_strict_rejects_preamble_but_salvage_accepts = unittest.skipIf(
        javalang is None, "javalang not installed"
    )(test_remediation_strict_rejects_preamble_but_salvage_accepts)


if __name__ == "__main__":
    unittest.main()
