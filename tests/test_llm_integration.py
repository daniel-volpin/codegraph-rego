import unittest
from unittest.mock import patch


class TestLlmIntegration(unittest.TestCase):
    @patch("codegraph.llm.integration.generate_chat_completion", return_value="ok")
    @patch("codegraph.llm.integration.extract_code_snippet", return_value="snippet")
    def test_explain_policy_violations_uses_target_method_fallback(self, mock_extract_code_snippet, _mock_llm) -> None:
        from codegraph.llm.integration import explain_policy_violations

        violations = [
            {
                "file_path": "Example.java",
                "target_method": "org.example.Foo.doPost(HttpServletRequest,HttpServletResponse)",
            }
        ]
        explain_policy_violations(violations, max_items=1, model="dummy")

        self.assertTrue(mock_extract_code_snippet.called)
        args, _kwargs = mock_extract_code_snippet.call_args
        # args: (file_path, needle)
        self.assertEqual(args[1], "doPost")


if __name__ == "__main__":
    unittest.main()
