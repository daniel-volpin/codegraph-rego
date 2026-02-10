import unittest

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

    def test_unified_diff(self):
        diff = self.service._unified_diff("a\nb", "a\nc", label="method")
        self.assertIn("-b", diff)
        self.assertIn("+c", diff)


if __name__ == "__main__":
    unittest.main()
