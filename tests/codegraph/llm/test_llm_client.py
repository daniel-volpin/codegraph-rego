import unittest
from unittest.mock import patch


class TestLlmClient(unittest.TestCase):
    @patch("codegraph.llm.client._DEFAULT_TRANSPORT")
    def test_generate_chat_completion_forwards_stop_sequences(self, mock_transport) -> None:
        from codegraph.llm.client import generate_chat_completion

        mock_transport.generate.return_value = "ok"

        result = generate_chat_completion(
            [{"role": "user", "content": "hello"}],
            model="dummy-model",
            stop=["<|im_end|>", "<|endoftext|>"],
        )

        self.assertEqual(result, "ok")
        request = mock_transport.generate.call_args.args[0]
        self.assertEqual(request.stop, ["<|im_end|>", "<|endoftext|>"])
        self.assertEqual(request.model, "dummy-model")

    @patch("codegraph.llm.client._DEFAULT_TRANSPORT")
    def test_generate_chat_completion_omits_stop_when_not_provided(self, mock_transport) -> None:
        from codegraph.llm.client import generate_chat_completion

        mock_transport.generate.return_value = "ok"

        result = generate_chat_completion(
            [{"role": "user", "content": "hello"}],
            model="dummy-model",
        )

        self.assertEqual(result, "ok")
        request = mock_transport.generate.call_args.args[0]
        self.assertIsNone(request.stop)


if __name__ == "__main__":
    unittest.main()
