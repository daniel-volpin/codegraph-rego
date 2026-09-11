from __future__ import annotations

import threading
from collections.abc import Callable
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from codegraph.config import Settings
from codegraph.llm.transport import openai_compatible_transport as transport
from codegraph.llm.transport import provider_admission
from codegraph.llm.transport.base import LLMRequest, LLMUnavailableError


def _successful_client() -> Mock:
    client = Mock()
    client.responses.create.return_value = SimpleNamespace(output_text="answer", status="completed")
    return client


def _blocking_client(entered: threading.Event, release: threading.Event) -> Mock:
    client = Mock()

    def create_response(**_: object) -> SimpleNamespace:
        entered.set()
        release.wait(timeout=2)
        return SimpleNamespace(output_text="answer", status="completed")

    client.responses.create.side_effect = create_response
    return client


def _track_active(
    client: Mock,
    tracker: dict[str, int],
    lock: threading.Lock,
    create_response_target: Callable[..., SimpleNamespace],
) -> Mock:
    def tracked_create_response(**kwargs: object) -> SimpleNamespace:
        with lock:
            tracker["active"] += 1
            tracker["max_active"] = max(tracker["max_active"], tracker["active"])
        try:
            return create_response_target(**kwargs)
        finally:
            with lock:
                tracker["active"] -= 1

    client.responses.create.side_effect = tracked_create_response
    return client


def _signal_provider_wait(monkeypatch: pytest.MonkeyPatch, gate: provider_admission.ProviderAdmissionGate) -> threading.Event:
    waiting = threading.Event()
    original_wait = provider_admission.Condition.wait

    def observed_wait(self: threading.Condition, timeout: float | None = None) -> bool:
        if self is gate._condition:
            waiting.set()
        return original_wait(self, timeout)

    monkeypatch.setattr(provider_admission.Condition, "wait", observed_wait)
    return waiting


def test_provider_admission_is_shared_across_transport_instances(monkeypatch) -> None:
    monkeypatch.setattr(
        transport,
        "settings",
        Settings(_env_file=None, llm_api_key="test-key", llm_max_concurrent_requests=1, llm_max_pending_requests=1),
    )
    entered = threading.Event()
    release_first = threading.Event()
    close_entered = threading.Event()
    release_close = threading.Event()
    waiter_entered = _signal_provider_wait(monkeypatch, transport.provider_admission_gate)
    active_tracker = {"active": 0, "max_active": 0}
    active_lock = threading.Lock()

    def create_blocking_response(**_: object) -> SimpleNamespace:
        entered.set()
        release_first.wait(timeout=2)
        return SimpleNamespace(output_text="answer", status="completed")

    client_one = Mock()
    client_one.close.side_effect = lambda: (close_entered.set(), release_close.wait(timeout=2))
    client_two = _track_active(
        Mock(),
        active_tracker,
        active_lock,
        lambda **_: SimpleNamespace(output_text="answer", status="completed"),
    )
    _track_active(client_one, active_tracker, active_lock, create_blocking_response)
    factory = Mock(side_effect=[client_one, client_two])
    monkeypatch.setattr(transport, "OpenAI", factory)

    first_result: list[str] = []
    second_result: list[str] = []
    request = LLMRequest(messages=[], raise_on_error=True)
    first = threading.Thread(target=lambda: first_result.append(transport.OpenAICompatibleTransport().generate(request)))
    second = threading.Thread(
        target=lambda: second_result.append(transport.OpenAICompatibleTransport().generate(request))
    )

    first.start()
    assert entered.wait(timeout=2)
    second.start()
    assert waiter_entered.wait(timeout=2)
    assert factory.call_count == 1
    release_first.set()
    assert close_entered.wait(timeout=2)
    assert factory.call_count == 1
    release_close.set()
    first.join(timeout=2)
    second.join(timeout=2)

    assert not first.is_alive()
    assert not second.is_alive()
    assert first_result == ["answer"]
    assert second_result == ["answer"]
    assert active_tracker["max_active"] == 1


def test_zero_wait_capacity_rejects_second_request_before_client_creation(monkeypatch) -> None:
    monkeypatch.setattr(
        transport,
        "settings",
        Settings(
            _env_file=None,
            llm_api_key="test-key",
            llm_max_concurrent_requests=1,
            llm_max_pending_requests=0,
            llm_queue_timeout_seconds=1.0,
        ),
    )
    entered = threading.Event()
    release_first = threading.Event()
    factory = Mock(return_value=_blocking_client(entered, release_first))
    monkeypatch.setattr(transport, "OpenAI", factory)

    first_result: list[str] = []
    first = threading.Thread(
        target=lambda: first_result.append(
            transport.OpenAICompatibleTransport().generate(LLMRequest(messages=[], raise_on_error=True))
        )
    )
    first.start()
    assert entered.wait(timeout=2)

    with pytest.raises(LLMUnavailableError, match="queue is full"):
        transport.OpenAICompatibleTransport().generate(LLMRequest(messages=[], raise_on_error=True))

    release_first.set()
    first.join(timeout=2)
    assert not first.is_alive()
    assert first_result == ["answer"]
    assert factory.call_count == 1


def test_bounded_queue_overflow_rejects_before_client_creation(monkeypatch) -> None:
    monkeypatch.setattr(
        transport,
        "settings",
        Settings(
            _env_file=None,
            llm_api_key="test-key",
            llm_max_concurrent_requests=1,
            llm_max_pending_requests=1,
            llm_queue_timeout_seconds=1.0,
        ),
    )
    entered = threading.Event()
    release_first = threading.Event()
    second_done = threading.Event()
    waiter_entered = _signal_provider_wait(monkeypatch, transport.provider_admission_gate)
    factory = Mock(side_effect=[_blocking_client(entered, release_first), _successful_client()])
    monkeypatch.setattr(transport, "OpenAI", factory)

    first = threading.Thread(
        target=lambda: transport.OpenAICompatibleTransport().generate(LLMRequest(messages=[], raise_on_error=True))
    )

    def run_second() -> None:
        transport.OpenAICompatibleTransport().generate(LLMRequest(messages=[], raise_on_error=True))
        second_done.set()

    second = threading.Thread(target=run_second)
    first.start()
    assert entered.wait(timeout=2)
    second.start()
    assert waiter_entered.wait(timeout=2)

    with pytest.raises(LLMUnavailableError, match="queue is full"):
        transport.OpenAICompatibleTransport().generate(LLMRequest(messages=[], raise_on_error=True))

    release_first.set()
    first.join(timeout=2)
    second.join(timeout=2)
    assert not first.is_alive()
    assert not second.is_alive()
    assert second_done.is_set()
    assert factory.call_count == 2


def test_expired_waiter_times_out_after_wakeup_before_client_creation(monkeypatch) -> None:
    monkeypatch.setattr(
        transport,
        "settings",
        Settings(
            _env_file=None,
            llm_api_key="test-key",
            llm_max_concurrent_requests=1,
            llm_max_pending_requests=1,
            llm_queue_timeout_seconds=5.0,
        ),
    )
    now = 0.0
    clock_lock = threading.Lock()

    def monotonic() -> float:
        with clock_lock:
            return now

    monkeypatch.setattr(provider_admission.time, "monotonic", monotonic)
    waiter_entered = _signal_provider_wait(monkeypatch, transport.provider_admission_gate)
    entered = threading.Event()
    release_first = threading.Event()
    factory = Mock(side_effect=[_blocking_client(entered, release_first), _successful_client()])
    monkeypatch.setattr(transport, "OpenAI", factory)

    first = threading.Thread(
        target=lambda: transport.OpenAICompatibleTransport().generate(LLMRequest(messages=[], raise_on_error=True))
    )
    waiter_error: list[BaseException] = []
    waiter = threading.Thread(
        target=lambda: waiter_error.append(
            pytest.raises(
                LLMUnavailableError,
                transport.OpenAICompatibleTransport().generate,
                LLMRequest(messages=[], raise_on_error=True),
            ).value
        )
    )

    first.start()
    assert entered.wait(timeout=2)
    waiter.start()
    assert waiter_entered.wait(timeout=2)
    with clock_lock:
        now = 6.0
    release_first.set()
    first.join(timeout=2)
    waiter.join(timeout=2)

    assert not first.is_alive()
    assert not waiter.is_alive()
    assert len(waiter_error) == 1
    assert "timed out" in str(waiter_error[0])
    assert factory.call_count == 1


def test_queued_base_exception_cleans_pending_capacity(monkeypatch) -> None:
    monkeypatch.setattr(
        transport,
        "settings",
        Settings(
            _env_file=None,
            llm_api_key="test-key",
            llm_max_concurrent_requests=1,
            llm_max_pending_requests=1,
            llm_queue_timeout_seconds=1.0,
        ),
    )
    entered = threading.Event()
    release_first = threading.Event()
    waiter_entered = threading.Event()
    original_wait = provider_admission.Condition.wait
    raise_for_waiter = True

    def interrupting_wait(self: threading.Condition, timeout: float | None = None) -> bool:
        nonlocal raise_for_waiter
        if self is transport.provider_admission_gate._condition and raise_for_waiter:
            raise_for_waiter = False
            waiter_entered.set()
            raise KeyboardInterrupt("queued stop")
        return original_wait(self, timeout)

    monkeypatch.setattr(provider_admission.Condition, "wait", interrupting_wait)
    factory = Mock(side_effect=[_blocking_client(entered, release_first), _successful_client()])
    monkeypatch.setattr(transport, "OpenAI", factory)
    first = threading.Thread(
        target=lambda: transport.OpenAICompatibleTransport().generate(LLMRequest(messages=[], raise_on_error=True))
    )
    queued_error: list[BaseException] = []
    interrupted = threading.Thread(
        target=lambda: queued_error.append(
            pytest.raises(
                KeyboardInterrupt,
                transport.OpenAICompatibleTransport().generate,
                LLMRequest(messages=[], raise_on_error=True),
            ).value
        )
    )

    first.start()
    assert entered.wait(timeout=2)
    interrupted.start()
    assert waiter_entered.wait(timeout=2)
    interrupted.join(timeout=2)
    assert not interrupted.is_alive()

    reusable_waiting = _signal_provider_wait(monkeypatch, transport.provider_admission_gate)
    reusable_done = threading.Event()
    reusable_result: list[str] = []
    reusable = threading.Thread(
        target=lambda: (
            reusable_result.append(transport.OpenAICompatibleTransport().generate(LLMRequest(messages=[]))),
            reusable_done.set(),
        )
    )
    reusable.start()
    assert reusable_waiting.wait(timeout=2)
    assert not reusable_done.is_set()
    release_first.set()
    first.join(timeout=2)
    reusable.join(timeout=2)

    assert not first.is_alive()
    assert not reusable.is_alive()
    assert len(queued_error) == 1
    assert str(queued_error[0]) == "queued stop"
    assert reusable_result == ["answer"]
    assert factory.call_count == 2


def test_provider_admission_queue_timeout_does_not_leak_slot(monkeypatch) -> None:
    monkeypatch.setattr(
        transport,
        "settings",
        Settings(
            _env_file=None,
            llm_api_key="test-key",
            llm_max_concurrent_requests=1,
            llm_max_pending_requests=1,
            llm_queue_timeout_seconds=0.01,
        ),
    )
    entered = threading.Event()
    release_first = threading.Event()
    factory = Mock(side_effect=[_blocking_client(entered, release_first), _successful_client()])
    monkeypatch.setattr(transport, "OpenAI", factory)

    first = threading.Thread(
        target=lambda: transport.OpenAICompatibleTransport().generate(LLMRequest(messages=[], raise_on_error=True))
    )
    first.start()
    assert entered.wait(timeout=2)

    with pytest.raises(LLMUnavailableError, match="timed out"):
        transport.OpenAICompatibleTransport().generate(LLMRequest(messages=[], raise_on_error=True))

    release_first.set()
    first.join(timeout=2)
    assert not first.is_alive()
    assert transport.OpenAICompatibleTransport().generate(LLMRequest(messages=[], raise_on_error=True)) == "answer"
    assert factory.call_count == 2


def test_provider_admission_gate_failure_honors_raise_on_error_false(monkeypatch) -> None:
    monkeypatch.setattr(
        transport,
        "settings",
        Settings(_env_file=None, llm_api_key="test-key", llm_max_concurrent_requests=1, llm_max_pending_requests=0),
    )
    entered = threading.Event()
    release_first = threading.Event()
    factory = Mock(return_value=_blocking_client(entered, release_first))
    monkeypatch.setattr(transport, "OpenAI", factory)

    first = threading.Thread(
        target=lambda: transport.OpenAICompatibleTransport().generate(LLMRequest(messages=[], raise_on_error=True))
    )
    first.start()
    assert entered.wait(timeout=2)

    result = transport.OpenAICompatibleTransport().generate(LLMRequest(messages=[], raise_on_error=False))

    release_first.set()
    first.join(timeout=2)
    assert not first.is_alive()
    assert "[LLM unavailable:" in result
    assert "queue is full" in result
    assert factory.call_count == 1


def test_provider_admission_releases_slot_after_provider_exception(monkeypatch) -> None:
    monkeypatch.setattr(
        transport,
        "settings",
        Settings(_env_file=None, llm_api_key="test-key", llm_max_concurrent_requests=1, llm_max_pending_requests=0),
    )
    failing_client = Mock()
    failing_client.responses.create.side_effect = TimeoutError("provider timed out")
    monkeypatch.setattr(transport, "OpenAI", Mock(side_effect=[failing_client, _successful_client()]))

    with pytest.raises(LLMUnavailableError, match="timed out"):
        transport.OpenAICompatibleTransport().generate(LLMRequest(messages=[], raise_on_error=True))

    assert transport.OpenAICompatibleTransport().generate(LLMRequest(messages=[], raise_on_error=True)) == "answer"


def test_provider_admission_releases_slot_after_base_exception(monkeypatch) -> None:
    monkeypatch.setattr(
        transport,
        "settings",
        Settings(_env_file=None, llm_api_key="test-key", llm_max_concurrent_requests=1, llm_max_pending_requests=0),
    )
    failing_client = Mock()
    failing_client.responses.create.side_effect = KeyboardInterrupt("stop")
    monkeypatch.setattr(transport, "OpenAI", Mock(side_effect=[failing_client, _successful_client()]))

    with pytest.raises(KeyboardInterrupt, match="stop"):
        transport.OpenAICompatibleTransport().generate(LLMRequest(messages=[], raise_on_error=True))

    assert transport.OpenAICompatibleTransport().generate(LLMRequest(messages=[], raise_on_error=True)) == "answer"
