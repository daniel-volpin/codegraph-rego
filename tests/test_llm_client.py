import unittest
from unittest.mock import patch


class TestLlmClient(unittest.TestCase):
    @patch("codegraph.llm.client.litellm")
    def test_generate_chat_completion_forwards_stop_sequences(self, mock_litellm) -> None:
        from codegraph.llm.client import generate_chat_completion

        mock_litellm.completion.return_value = {
            "choices": [{"message": {"content": "ok"}}],
        }

        result = generate_chat_completion(
            [{"role": "user", "content": "hello"}],
            model="dummy-model",
            stop=["<|im_end|>", "<|endoftext|>"],
        )

        self.assertEqual(result, "ok")
        _args, kwargs = mock_litellm.completion.call_args
        self.assertEqual(kwargs["stop"], ["<|im_end|>", "<|endoftext|>"])

    @patch("codegraph.llm.client.litellm")
    def test_generate_chat_completion_omits_stop_when_not_provided(self, mock_litellm) -> None:
        from codegraph.llm.client import generate_chat_completion

        mock_litellm.completion.return_value = {
            "choices": [{"message": {"content": "ok"}}],
        }

        result = generate_chat_completion(
            [{"role": "user", "content": "hello"}],
            model="dummy-model",
        )

        self.assertEqual(result, "ok")
        _args, kwargs = mock_litellm.completion.call_args
        self.assertNotIn("stop", kwargs)


if __name__ == "__main__":
    unittest.main()
