import logging
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from codegraph.config import Settings
from codegraph.llm.transport import openai_compatible_transport as transport
from codegraph.llm.transport.base import LLMRequest, LLMUnavailableError


class _SyntheticAbort(BaseException):
    pass


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


@pytest.mark.parametrize(
    ("finish_reason", "expected_error"),
    [
        ("length", "incomplete"),
        ("content_filter", "blocked"),
    ],
)
def test_chat_completion_unfinished_or_blocked_finish_reason_rejects_parseable_content(
    finish_reason: str, expected_error: str
) -> None:
    response = SimpleNamespace(
        choices=[
            SimpleNamespace(
                finish_reason=finish_reason,
                message=SimpleNamespace(content='{"edit": "candidate"}'),
            )
        ],
    )
    with pytest.raises(LLMUnavailableError, match=expected_error):
        transport._extract_message_content(response)


def test_chat_completion_missing_finish_reason_keeps_compatible_content_acceptance() -> None:
    response = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content='{"edit": "candidate"}'))],
    )
    assert transport._extract_message_content(response) == '{"edit": "candidate"}'


def test_responses_refusal_wins_over_output_text() -> None:
    response = SimpleNamespace(
        status="completed",
        output_text='{"edit": "candidate"}',
        output=[
            SimpleNamespace(
                content=[
                    SimpleNamespace(type="output_text", text='{"edit": "candidate"}'),
                    SimpleNamespace(type="refusal", text="blocked"),
                ]
            )
        ],
    )
    with pytest.raises(LLMUnavailableError, match="refused"):
        transport._extract_responses_output_text(response)


def test_responses_completed_text_is_preserved_from_output_parts() -> None:
    response = SimpleNamespace(
        status="completed",
        output=[
            SimpleNamespace(
                content=[
                    SimpleNamespace(type="output_text", text='{"edit": '),
                    SimpleNamespace(type="text", text='"candidate"}'),
                ]
            )
        ],
    )
    assert transport._extract_responses_output_text(response) == '{"edit": "candidate"}'


def test_close_failure_after_success_raise_on_error_false_returns_unavailable(monkeypatch) -> None:
    monkeypatch.setattr(transport, "settings", Settings(_env_file=None, llm_api_key="test-key"))
    client = Mock()
    client.responses.create.return_value = SimpleNamespace(output_text="answer", status="completed")
    client.close.side_effect = OSError("close boom")
    monkeypatch.setattr(transport, "OpenAI", Mock(return_value=client))

    result = transport.OpenAICompatibleTransport().generate(LLMRequest(messages=[], raise_on_error=False))
    assert "[LLM unavailable:" in result
    assert "cleanup failed" in result
    assert "close boom" in result


def test_close_failure_after_success_raise_on_error_true_raises_unavailable(monkeypatch) -> None:
    monkeypatch.setattr(transport, "settings", Settings(_env_file=None, llm_api_key="test-key"))
    client = Mock()
    client.responses.create.return_value = SimpleNamespace(output_text="answer", status="completed")
    client.close.side_effect = OSError("close boom")
    monkeypatch.setattr(transport, "OpenAI", Mock(return_value=client))

    with pytest.raises(LLMUnavailableError, match="cleanup failed"):
        transport.OpenAICompatibleTransport().generate(LLMRequest(messages=[], raise_on_error=True))


def test_close_failure_does_not_mask_generation_failure_raise_on_error_false(monkeypatch) -> None:
    monkeypatch.setattr(transport, "settings", Settings(_env_file=None, llm_api_key="test-key"))
    client = Mock()
    client.responses.create.side_effect = TimeoutError("timed out")
    client.close.side_effect = OSError("close boom")
    monkeypatch.setattr(transport, "OpenAI", Mock(return_value=client))

    result = transport.OpenAICompatibleTransport().generate(LLMRequest(messages=[], raise_on_error=False))
    assert "timed out" in result
    assert "close boom" not in result


def test_close_failure_does_not_mask_generation_failure_raise_on_error_true(monkeypatch) -> None:
    monkeypatch.setattr(transport, "settings", Settings(_env_file=None, llm_api_key="test-key"))
    client = Mock()
    client.responses.create.side_effect = TimeoutError("timed out")
    client.close.side_effect = OSError("close boom")
    monkeypatch.setattr(transport, "OpenAI", Mock(return_value=client))

    with pytest.raises(LLMUnavailableError, match="timed out"):
        transport.OpenAICompatibleTransport().generate(LLMRequest(messages=[], raise_on_error=True))


@pytest.mark.parametrize("abort_exc", [KeyboardInterrupt("stop"), _SyntheticAbort("abort")])
def test_base_exception_abort_propagates_and_still_closes_client_once(
    monkeypatch, caplog: pytest.LogCaptureFixture, abort_exc: BaseException
) -> None:
    monkeypatch.setattr(transport, "settings", Settings(_env_file=None, llm_api_key="test-key"))
    client = Mock()
    client.responses.create.side_effect = abort_exc
    client.close.side_effect = OSError("close boom")
    monkeypatch.setattr(transport, "OpenAI", Mock(return_value=client))

    with caplog.at_level(logging.WARNING, logger="codegraph.llm.transport.openai_compatible"):
        with pytest.raises(type(abort_exc), match=str(abort_exc)):
            transport.OpenAICompatibleTransport().generate(LLMRequest(messages=[], raise_on_error=False))
    client.close.assert_called_once()
    close_logs = [record.message for record in caplog.records if "Failed to close LLM client cleanly" in record.message]
    assert len(close_logs) == 1
