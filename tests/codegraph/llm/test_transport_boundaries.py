from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from codegraph.config import Settings
from codegraph.llm.transport import openai_compatible_transport as transport
from codegraph.llm.transport.base import LLMRequest, LLMUnavailableError


def test_explicit_chat_endpoint_works_for_non_local_provider(monkeypatch) -> None:
    monkeypatch.setattr(
        transport, "settings",
        Settings(_env_file=None, llm_api_base="https://provider.invalid/v1", llm_api_mode="chat_completions"),
    )
    client = Mock()
    client.chat.completions.create.return_value = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content="answer"))],
    )
    client.responses.create.side_effect = AssertionError("provider does not implement Responses")
    monkeypatch.setattr(transport, "OpenAI", Mock(return_value=client))
    result = transport.OpenAICompatibleTransport().generate(LLMRequest(messages=[], raise_on_error=True))
    assert result == "answer"


def test_configured_timeouts_retries_and_parameter_support_reach_sdk(monkeypatch) -> None:
    monkeypatch.setattr(
        transport, "settings",
        Settings(
            _env_file=None, llm_api_mode="responses", llm_api_key="test-key",
            llm_timeout_seconds=12, llm_max_retries=1, llm_send_temperature=False,
        ),
    )
    client = Mock()
    client.responses.create.return_value = SimpleNamespace(output_text="answer", status="completed")
    factory = Mock(return_value=client)
    monkeypatch.setattr(transport, "OpenAI", factory)
    result = transport.OpenAICompatibleTransport().generate(LLMRequest(messages=[], max_tokens=17, raise_on_error=True))
    assert result == "answer"
    assert factory.call_args.kwargs["timeout"] == 12
    assert factory.call_args.kwargs["max_retries"] == 1
    assert "temperature" not in client.responses.create.call_args.kwargs
    assert client.responses.create.call_args.kwargs["max_output_tokens"] == 17
    client.close.assert_called_once()


def test_client_is_closed_after_provider_failure(monkeypatch) -> None:
    monkeypatch.setattr(transport, "settings", Settings(_env_file=None, llm_api_key="test-key"))
    client = Mock()
    client.responses.create.side_effect = TimeoutError("timed out")
    monkeypatch.setattr(transport, "OpenAI", Mock(return_value=client))
    with pytest.raises(LLMUnavailableError, match="timed out"):
        transport.OpenAICompatibleTransport().generate(LLMRequest(messages=[], raise_on_error=True))
    client.close.assert_called_once()


def test_refusal_is_not_accepted_as_a_candidate() -> None:
    response = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content='{"edit": "candidate"}', refusal="refused"))],
    )
    with pytest.raises(LLMUnavailableError, match="refused"):
        transport._extract_message_content(response, allow_reasoning_content=True)


def test_incomplete_response_is_not_accepted_as_a_candidate() -> None:
    response = SimpleNamespace(status="incomplete", output_text='{"edit": "candidate"}')
    with pytest.raises(LLMUnavailableError, match="incomplete"):
        transport._extract_responses_output_text(response)
