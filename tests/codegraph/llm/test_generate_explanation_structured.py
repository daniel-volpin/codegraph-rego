import unittest
from unittest.mock import patch


class TestGeneratePolicyExplanationStructured(unittest.TestCase):
    @patch("codegraph.llm.services.explanation_service.build_explanation_prompt", return_value=[{"role": "user", "content": "prompt"}])
    @patch(
        "codegraph.llm.services.explanation_service.build_explanation_evidence",
        return_value={"evidence_cards": [{"id": "E1", "citation": "src/Foo.java lines 10-18"}]},
    )
    def test_generate_policy_explanation_structured_extracts_json_object_from_preamble(
        self,
        _mock_build_evidence,
        mock_build_prompt,
    ) -> None:
        from codegraph.llm.integration import generate_policy_explanation_structured

        captured = {}

        def fake_llm(messages, **kwargs):
            captured["messages"] = messages
            captured["kwargs"] = kwargs
            return 'Thinking Process:\n1. Analyze\n{"evidence_id":"E1","why":"Weak hash is insecure.","fix":"Use SHA-256."}\nExtra'

        violation = {"violation_id": "ISO-A.10-WEAK-HASH", "evidence": {}}
        result = generate_policy_explanation_structured(
            violation,
            include_graph_context=True,
            evidence_mode="lean",
            max_tokens=192,
            model="dummy-model",
            llm_client=fake_llm,
        )

        self.assertEqual(
            result,
            {
                "evidence_id": "E1",
                "citation": "src/Foo.java lines 10-18",
                "why": "Weak hash is insecure.",
                "fix": "Use SHA-256.",
            },
        )
        mock_build_prompt.assert_called_once_with(
            violation,
            include_graph_context=True,
            evidence_mode="lean",
            structured_output=True,
        )
        kwargs = captured["kwargs"]
        self.assertEqual(kwargs["stop"], ["<|im_end|>", "<|endoftext|>"])
        self.assertEqual(kwargs["response_format"]["type"], "json_schema")

    @patch("codegraph.llm.services.explanation_service.build_explanation_prompt", return_value=[{"role": "user", "content": "prompt"}])
    @patch(
        "codegraph.llm.services.explanation_service.build_explanation_evidence",
        return_value={"evidence_cards": [{"id": "E1", "citation": "src/Foo.java lines 10-18"}]},
    )
    def test_generate_policy_explanation_structured_rejects_invalid_payload(
        self,
        _mock_build_evidence,
        _mock_build_prompt,
    ) -> None:
        from codegraph.llm.integration import generate_policy_explanation_structured

        violation = {"violation_id": "ISO-A.10-WEAK-HASH", "evidence": {}}
        with self.assertRaisesRegex(ValueError, "invalid structured explanation payload"):
            generate_policy_explanation_structured(
                violation,
                include_graph_context=True,
                evidence_mode="lean",
                max_tokens=192,
                model="dummy-model",
                llm_client=lambda *_args, **_kwargs: "Thinking Process:\n1. Analyze\n2. Explain",
            )

    @patch("codegraph.llm.services.explanation_service.build_explanation_prompt", return_value=[{"role": "user", "content": "prompt"}])
    @patch(
        "codegraph.llm.services.explanation_service.build_explanation_evidence",
        return_value={"evidence_cards": []},
    )
    def test_generate_policy_explanation_structured_accepts_labeled_plain_text(
        self,
        _mock_build_evidence,
        _mock_build_prompt,
    ) -> None:
        from codegraph.llm.integration import generate_policy_explanation_structured

        violation = {"violation_id": "ISO-A.10-WEAK-HASH", "evidence": {}}
        result = generate_policy_explanation_structured(
            violation,
            include_graph_context=True,
            evidence_mode="lean",
            max_tokens=192,
            model="dummy-model",
            llm_client=lambda *_args, **_kwargs: "Citation: src/Foo.java:10-18\nWhy: Weak hash is insecure.\nFix: Use SHA-256.",
        )

        self.assertEqual(
            result,
            {
                "citation": "src/Foo.java:10-18",
                "why": "Weak hash is insecure.",
                "fix": "Use SHA-256.",
            },
        )

    @patch("codegraph.llm.services.explanation_service.build_explanation_prompt", return_value=[{"role": "user", "content": "prompt"}])
    @patch(
        "codegraph.llm.services.explanation_service.build_explanation_evidence",
        return_value={"evidence_cards": [{"id": "E1", "citation": "src/Foo.java lines 10-18"}]},
    )
    def test_generate_policy_explanation_structured_rejects_unknown_evidence_id(
        self,
        _mock_build_evidence,
        _mock_build_prompt,
    ) -> None:
        from codegraph.llm.integration import generate_policy_explanation_structured

        violation = {"violation_id": "ISO-A.10-WEAK-HASH", "evidence": {}}
        with self.assertRaisesRegex(ValueError, "unknown evidence_id"):
            generate_policy_explanation_structured(
                violation,
                include_graph_context=True,
                evidence_mode="lean",
                max_tokens=192,
                model="dummy-model",
                llm_client=lambda *_args, **_kwargs: '{"evidence_id":"E99","why":"Weak hash is insecure.","fix":"Use SHA-256."}',
            )

    @patch("codegraph.llm.services.explanation_service.build_explanation_prompt", return_value=[{"role": "user", "content": "prompt"}])
    @patch(
        "codegraph.llm.services.explanation_service.build_explanation_evidence",
        return_value={"evidence_cards": [{"id": "E1", "citation": "src/Foo.java lines 10-18"}]},
    )
    def test_generate_policy_explanation_structured_strict_mode_rejects_salvage_only_payload(
        self,
        _mock_build_evidence,
        _mock_build_prompt,
    ) -> None:
        from codegraph.llm.integration import generate_policy_explanation_structured

        violation = {"violation_id": "ISO-A.10-WEAK-HASH", "evidence": {}}
        with self.assertRaisesRegex(ValueError, "invalid structured explanation payload"):
            generate_policy_explanation_structured(
                violation,
                include_graph_context=True,
                evidence_mode="lean",
                max_tokens=192,
                model="dummy-model",
                parse_mode="strict",
                llm_client=lambda *_args, **_kwargs: (
                    'Thinking Process:\n1. Analyze\n{"evidence_id":"E1","why":"Weak hash is insecure.","fix":"Use SHA-256."}'
                ),
            )


if __name__ == "__main__":
    unittest.main()
