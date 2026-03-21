import unittest
from unittest.mock import patch


class TestExplainPolicyViolations(unittest.TestCase):
    @patch("codegraph.llm.services.explanation_service.generate_chat_completion", return_value="ok")
    @patch("codegraph.llm.services.explanation_service.extract_code_snippet", return_value="snippet")
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


class TestGeneratePolicyExplanation(unittest.TestCase):
    @patch("codegraph.llm.services.explanation_service.build_explanation_prompt", return_value=[{"role": "user", "content": "prompt"}])
    def test_generate_policy_explanation_passes_evidence_mode_and_max_tokens(
        self,
        mock_build_prompt,
    ) -> None:
        from codegraph.llm.integration import generate_policy_explanation

        captured = {}

        def fake_llm(messages, **kwargs):
            captured["messages"] = messages
            captured["kwargs"] = kwargs
            return "ok"

        violation = {"violation_id": "ISO-A.10-WEAK-HASH", "evidence": {}}
        result = generate_policy_explanation(
            violation,
            include_graph_context=True,
            evidence_mode="lean",
            max_tokens=192,
            model="dummy-model",
            llm_client=fake_llm,
        )

        self.assertEqual(result, "ok")
        mock_build_prompt.assert_called_once_with(
            violation,
            include_graph_context=True,
            evidence_mode="lean",
            structured_output=False,
        )
        kwargs = captured["kwargs"]
        self.assertEqual(kwargs["model"], "dummy-model")
        self.assertEqual(kwargs["max_tokens"], 192)
        self.assertIsNone(kwargs["stop"])
        self.assertIsNone(kwargs["response_format"])

    @patch(
        "codegraph.llm.services.explanation_service.build_explanation_prompt",
        return_value=[{"role": "user", "content": "prompt"}],
    )
    @patch(
        "codegraph.llm.services.explanation_service.build_explanation_evidence",
        return_value={"evidence_cards": [{"id": "E1", "citation": "src/Foo.java lines 10-18"}]},
    )
    def test_generate_policy_explanation_structured_output_renders_plain_text(
        self,
        _mock_build_evidence,
        mock_build_prompt,
    ) -> None:
        from codegraph.llm.integration import generate_policy_explanation

        captured = {}

        def fake_llm(messages, **kwargs):
            captured["messages"] = messages
            captured["kwargs"] = kwargs
            return '{"evidence_id":"E1","why":"Weak hash is insecure.","fix":"Use SHA-256."}'

        violation = {"violation_id": "ISO-A.10-WEAK-HASH", "evidence": {}}
        result = generate_policy_explanation(
            violation,
            include_graph_context=True,
            evidence_mode="lean",
            structured_output=True,
            max_tokens=192,
            model="dummy-model",
            llm_client=fake_llm,
        )

        self.assertEqual(
            result,
            "Citation: src/Foo.java lines 10-18\nWhy: Weak hash is insecure.\nFix: Use SHA-256.",
        )
        mock_build_prompt.assert_called_once_with(
            violation,
            include_graph_context=True,
            evidence_mode="lean",
            structured_output=True,
        )
        kwargs = captured["kwargs"]
        self.assertEqual(kwargs["model"], "dummy-model")
        self.assertEqual(kwargs["max_tokens"], 192)
        self.assertEqual(kwargs["stop"], ["<|im_end|>", "<|endoftext|>"])
        self.assertEqual(kwargs["response_format"]["type"], "json_schema")
        self.assertEqual(kwargs["response_format"]["json_schema"]["schema"]["required"], ["evidence_id", "why", "fix"])

    @patch("codegraph.llm.services.explanation_service.build_explanation_prompt", return_value=[{"role": "user", "content": "prompt"}])
    @patch(
        "codegraph.llm.services.explanation_service.build_explanation_evidence",
        return_value={"evidence_cards": [{"id": "E1", "citation": "src/Foo.java lines 10-18"}]},
    )
    def test_generate_policy_explanation_structured_output_strips_trailing_tokens(
        self,
        _mock_build_evidence,
        _mock_build_prompt,
    ) -> None:
        from codegraph.llm.integration import generate_policy_explanation

        violation = {"violation_id": "ISO-A.10-WEAK-HASH", "evidence": {}}
        result = generate_policy_explanation(
            violation,
            include_graph_context=True,
            evidence_mode="lean",
            structured_output=True,
            max_tokens=192,
            model="dummy-model",
            llm_client=lambda *_args, **_kwargs: '{"evidence_id":"E1","why":"Weak hash is insecure.","fix":"Use SHA-256."}<|im_end|><|im_end|>',
        )

        self.assertEqual(
            result,
            "Citation: src/Foo.java lines 10-18\nWhy: Weak hash is insecure.\nFix: Use SHA-256.",
        )


if __name__ == "__main__":
    unittest.main()
