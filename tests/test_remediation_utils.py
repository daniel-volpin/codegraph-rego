import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

try:
    import javalang  # noqa: F401
except ImportError:  # pragma: no cover - environment guard
    javalang = None


@unittest.skipIf(javalang is None, "javalang not installed")
class RemediationUtilsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from codegraph.remediation import service

        cls.service = service

    def test_extract_json_block(self):
        text = "Here is output:\n```json\n{\"updated_source_code\": \"ok\"}\n```"
        extracted = self.service._extract_json_block(text)
        self.assertEqual(extracted, "{\"updated_source_code\": \"ok\"}")

    def test_parse_llm_virtual_json(self):
        raw = "note\n{\"updated_source_code\": \"public void foo() {}\", \"explanation\": \"ok\"}"
        parsed = self.service.RemediationService._parse_llm_virtual_json(raw)
        self.assertEqual(parsed["updated_source_code"], "public void foo() {}")
        self.assertEqual(parsed["explanation"], "ok")

    def test_parse_llm_virtual_json_sample_payload(self):
        raw = (
            '{"updated_source_code":"public void doPost(HttpServletRequest request, '
            'HttpServletResponse response) {'
            'java.security.MessageDigest md = java.security.MessageDigest.getInstance(\\"SHA-256\\");'
            '}","explanation":"Switched weak hash to SHA-256."}'
        )
        parsed = self.service.RemediationService._parse_llm_virtual_json(raw)
        self.assertIsNone(parsed.get("parse_error"))
        self.assertGreater(len(parsed["updated_source_code"]), 0)
        self.assertEqual(parsed["explanation"], "Switched weak hash to SHA-256.")

    def test_parse_llm_virtual_json_replacement_method_code(self):
        raw = (
            '{"file_path":"Example.java","target_method_signature":"example.Foo.doPost(HttpServletRequest,HttpServletResponse)",'
            '"replacement_method_code":"public void doPost(HttpServletRequest request, HttpServletResponse response) {\\n'
            'java.security.MessageDigest md = java.security.MessageDigest.getInstance(\\"SHA-256\\");\\n}",'
            '"explanation":"Structured output patch."}'
        )
        parsed = self.service.RemediationService._parse_llm_virtual_json(raw)
        self.assertIsNone(parsed.get("parse_error"))
        self.assertIn("SHA-256", parsed["updated_source_code"])

    def test_capture_raw_llm_output_on_invalid_json(self):
        invalid_raw = '{"updated_source_code":"public void foo() {}"'
        parsed = self.service.RemediationService._parse_llm_virtual_json(invalid_raw)
        self.assertTrue((parsed.get("parse_error") or "").startswith("invalid_json"))
        with TemporaryDirectory() as tmp:
            out = self.service._capture_raw_llm_output(
                tmp, "BenchmarkTest99999", 1, invalid_raw
            )
            self.assertIsNotNone(out)
            self.assertTrue(Path(out).is_file())
            self.assertEqual(Path(out).read_text(encoding="utf-8"), invalid_raw)

    def test_parse_llm_virtual_json_rejects_unescaped_quotes_in_code(self):
        # This mimics the real failure mode in remediation_eval: the model returns JSON-like text,
        # but embeds raw `"` from Java string literals inside a JSON string field.
        raw = (
            '{"file_path":"Example.java","target_method_signature":"x.y.Foo.doPost(A,B)",'
            '"replacement_method_code":"public void doPost(A a, B b) { System.out.println("hi"); }"}'
        )
        parsed = self.service.RemediationService._parse_llm_virtual_json(raw)
        self.assertTrue((parsed.get("parse_error") or "").startswith("invalid_json"))

    def test_parse_llm_virtual_json_accepts_code_only_output(self):
        raw = "public void doPost(A a, B b) { return; }"
        parsed = self.service.RemediationService._parse_llm_virtual_json(raw)
        self.assertIsNone(parsed.get("parse_error"))
        self.assertEqual(parsed["updated_source_code"], raw)

    def test_parse_llm_virtual_json_accepts_fenced_code_block(self):
        raw = "```java\npublic void doPost(A a, B b) { return; }\n```"
        parsed = self.service.RemediationService._parse_llm_virtual_json(raw)
        self.assertIsNone(parsed.get("parse_error"))
        self.assertIn("public void doPost", parsed["updated_source_code"])

    def test_unified_diff(self):
        diff = self.service._unified_diff("a\nb", "a\nc", label="method")
        self.assertIn("-b", diff)
        self.assertIn("+c", diff)


if __name__ == "__main__":
    unittest.main()
