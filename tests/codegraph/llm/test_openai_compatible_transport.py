import unittest
from types import SimpleNamespace
from unittest.mock import patch

from codegraph.llm.transport.base import LLMRequest
from codegraph.llm.transport.openai_compatible_transport import OpenAICompatibleTransport


class TestOpenAICompatibleTransport(unittest.TestCase):
    @patch("codegraph.llm.transport.openai_compatible_transport.OpenAI")
    def test_lm_studio_structured_output_uses_chat_completions(self, mock_openai_cls) -> None:
        mock_client = mock_openai_cls.return_value
        mock_client.chat.completions.create.return_value = SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content='{"ok":true}'))]
        )

        request = LLMRequest(
            messages=[{"role": "user", "content": "hello"}],
            model="dummy-model",
            stop=["<|im_end|>", "<|endoftext|>"],
            response_format={
                "type": "json_schema",
                "json_schema": {
                    "name": "policy_explanation",
                    "strict": True,
                    "schema": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {"citation": {"type": "string"}},
                        "required": ["citation"],
                    },
                },
            },
        )

        with patch("codegraph.llm.transport.openai_compatible_transport.settings.llm_api_base", "http://localhost:1234/v1"):
            with patch("codegraph.llm.transport.openai_compatible_transport.settings.llm_api_key", None):
                transport = OpenAICompatibleTransport()
                result = transport.generate(request)

        self.assertEqual(result, '{"ok":true}')
        mock_client.chat.completions.create.assert_called_once()
        mock_client.responses.create.assert_not_called()
        kwargs = mock_client.chat.completions.create.call_args.kwargs
        self.assertEqual(kwargs["model"], "dummy-model")
        self.assertEqual(kwargs["stop"], ["<|im_end|>", "<|endoftext|>"])
        self.assertEqual(kwargs["response_format"]["type"], "json_schema")

    @patch("codegraph.llm.transport.openai_compatible_transport.OpenAI")
    def test_hosted_structured_output_uses_responses(self, mock_openai_cls) -> None:
        mock_client = mock_openai_cls.return_value
        mock_client.responses.create.return_value = SimpleNamespace(output_text='{"citation":"x"}')

        request = LLMRequest(
            messages=[{"role": "user", "content": "hello"}],
            model="gpt-4o-mini",
            response_format={
                "type": "json_schema",
                "json_schema": {
                    "name": "policy_explanation",
                    "strict": True,
                    "schema": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {"citation": {"type": "string"}},
                        "required": ["citation"],
                    },
                },
            },
        )

        with patch("codegraph.llm.transport.openai_compatible_transport.settings.llm_api_base", None):
            with patch("codegraph.llm.transport.openai_compatible_transport.settings.llm_api_key", "test-key"):
                transport = OpenAICompatibleTransport()
                result = transport.generate(request)

        self.assertEqual(result, '{"citation":"x"}')
        mock_client.responses.create.assert_called_once()
        mock_client.chat.completions.create.assert_not_called()
        kwargs = mock_client.responses.create.call_args.kwargs
        self.assertEqual(kwargs["model"], "gpt-4o-mini")
        self.assertEqual(kwargs["text"]["format"]["type"], "json_schema")


if __name__ == "__main__":
    unittest.main()
