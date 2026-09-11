from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager
from threading import Condition

from codegraph.llm.transport.base import LLMUnavailableError


class ProviderAdmissionGate:
    def __init__(self) -> None:
        self._condition = Condition()
        self._active = 0
        self._waiting = 0

    @contextmanager
    def acquire(self, *, max_active: int, max_waiting: int, queue_timeout_seconds: float) -> Iterator[None]:
        self._acquire(max_active=max_active, max_waiting=max_waiting, queue_timeout_seconds=queue_timeout_seconds)
        try:
            yield
        finally:
            self.release()

    def _acquire(self, *, max_active: int, max_waiting: int, queue_timeout_seconds: float) -> None:
        deadline = time.monotonic() + queue_timeout_seconds
        with self._condition:
            if self._active < max_active:
                self._active += 1
                return
            if self._waiting >= max_waiting:
                raise LLMUnavailableError("LLM provider admission queue is full.")

            self._waiting += 1
            admitted = False
            try:
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise LLMUnavailableError("LLM provider admission queue timed out.")
                    self._condition.wait(timeout=remaining)
                    if deadline - time.monotonic() <= 0:
                        raise LLMUnavailableError("LLM provider admission queue timed out.")
                    if self._active < max_active:
                        self._active += 1
                        admitted = True
                        return
            finally:
                self._waiting -= 1
                if not admitted and self._active < max_active:
                    self._condition.notify()

    def release(self) -> None:
        with self._condition:
            self._active -= 1
            self._condition.notify()


provider_admission_gate = ProviderAdmissionGate()
