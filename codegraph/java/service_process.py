from __future__ import annotations

import os
import selectors
import subprocess
import time
from collections.abc import Iterator
from contextlib import contextmanager
from threading import Condition
from typing import Any

from pydantic import BaseModel

EXPECTED_BACKEND = "eclipse-jdt"
JDT_BACKEND_VERSION = "3.47.0"
ADAPTER_VERSION = "0.1.0"
RESPONSE_SCHEMA_VERSION = "codegraph-java/v1"
_MAX_PENDING_JAVA_REQUESTS = 4
_STDERR_EXCERPT_BYTES = 4096


class JavaParserError(RuntimeError):
    """Base class for Java parser process-boundary failures."""


class JavaParserUnavailableError(JavaParserError):
    """The Java parser executable, jar, or subprocess was unavailable."""


class JavaParserProtocolError(JavaParserError):
    """The Java parser subprocess violated the JSON protocol."""


class JavaParserTimeoutError(JavaParserError):
    """The Java parser subprocess exceeded its configured deadline."""


class JavaParserInputError(JavaParserError, ValueError):
    """The caller supplied invalid parser input."""


class _JavaParserAdmissionGate:
    def __init__(self) -> None:
        self._condition = Condition()
        self._active = 0
        self._waiting = 0

    @contextmanager
    def acquire(self, *, max_active: int, queue_timeout_seconds: float) -> Iterator[None]:
        self._acquire(max_active=max_active, queue_timeout_seconds=queue_timeout_seconds)
        try:
            yield
        finally:
            self.release()

    def _acquire(self, *, max_active: int, queue_timeout_seconds: float) -> None:
        deadline = time.monotonic() + queue_timeout_seconds
        with self._condition:
            if self._active < max_active:
                self._active += 1
                return
            if self._waiting >= _MAX_PENDING_JAVA_REQUESTS:
                raise JavaParserUnavailableError("Java parser admission queue is full.")

            self._waiting += 1
            admitted = False
            try:
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise JavaParserUnavailableError("Java parser admission queue timed out.")
                    self._condition.wait(timeout=remaining)
                    if deadline - time.monotonic() <= 0:
                        raise JavaParserUnavailableError("Java parser admission queue timed out.")
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


_java_parser_gate = _JavaParserAdmissionGate()


def _collect_process_output(
    process: subprocess.Popen[bytes],
    request_bytes: bytes,
    *,
    timeout_seconds: float,
    max_stdout_bytes: int,
) -> tuple[bytes, bytes, int]:
    stdout = bytearray()
    stderr = bytearray()
    stderr_truncated = False
    written = 0
    write_error: BrokenPipeError | None = None

    selector = selectors.DefaultSelector()
    assert process.stdin is not None
    assert process.stdout is not None
    assert process.stderr is not None

    deadline = time.monotonic() + timeout_seconds
    try:
        for stream, event, name in (
            (process.stdin, selectors.EVENT_WRITE, "stdin"),
            (process.stdout, selectors.EVENT_READ, "stdout"),
            (process.stderr, selectors.EVENT_READ, "stderr"),
        ):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, event, name)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise JavaParserTimeoutError(f"Java parser timed out after {timeout_seconds} seconds.")
            events = selector.select(timeout=min(remaining, 0.05))
            for key, _ in events:
                stream = key.fileobj
                if key.data == "stdin":
                    try:
                        written += os.write(stream.fileno(), request_bytes[written:written + 8192])
                    except BlockingIOError:
                        continue
                    except BrokenPipeError as exc:
                        write_error = exc
                    if write_error is not None or written == len(request_bytes):
                        selector.unregister(stream)
                        stream.close()
                    continue
                try:
                    chunk = os.read(stream.fileno(), 8192)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(stream)
                    continue
                if key.data == "stdout":
                    stdout.extend(chunk)
                    if len(stdout) > max_stdout_bytes:
                        raise JavaParserProtocolError(
                            f"Java parser stdout exceeded java_parser_max_output_bytes ({max_stdout_bytes})."
                        )
                elif len(stderr) < _STDERR_EXCERPT_BYTES:
                    remaining_stderr = _STDERR_EXCERPT_BYTES - len(stderr)
                    stderr.extend(chunk[:remaining_stderr])
                    stderr_truncated = stderr_truncated or len(chunk) > remaining_stderr
                else:
                    stderr_truncated = True
        return_code = process.wait(timeout=max(0.0, deadline - time.monotonic()))
    except subprocess.TimeoutExpired as exc:
        raise JavaParserTimeoutError(f"Java parser timed out after {timeout_seconds} seconds.") from exc
    finally:
        selector.close()

    if write_error is not None and return_code == 0:
        raise JavaParserProtocolError("Java parser closed its input before receiving the complete request.") from write_error
    if stderr_truncated:
        stderr.extend(b"\n...[stderr truncated]...")
    return bytes(stdout), bytes(stderr), return_code


def _kill_and_reap(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.kill()
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=1)


def _child_environment() -> dict[str, str]:
    child_env: dict[str, str] = {}
    for name in ("LANG", "LC_ALL"):
        value = os.environ.get(name)
        if value:
            child_env[name] = value
    return child_env


def _stderr_excerpt(stderr: bytes) -> str:
    if not stderr:
        return "<empty>"
    return stderr.decode("utf-8", errors="replace")


def _verify_required_protocol_fields(response_json: Any) -> None:
    if not isinstance(response_json, dict):
        raise JavaParserProtocolError("Java parser response must be a JSON object.")
    if response_json.get("schema_version") != RESPONSE_SCHEMA_VERSION:
        raise JavaParserProtocolError("Java parser response schema_version did not match codegraph-java/v1.")
    provenance = response_json.get("provenance")
    if not isinstance(provenance, dict):
        raise JavaParserProtocolError("Java parser response provenance must be an object.")
    if provenance.get("backend") != EXPECTED_BACKEND:
        raise JavaParserProtocolError("Java parser response provenance.backend did not match eclipse-jdt.")
    if provenance.get("backend_version") != JDT_BACKEND_VERSION:
        raise JavaParserProtocolError("Java parser response provenance.backend_version did not match 3.47.0.")
    if provenance.get("adapter_version") != ADAPTER_VERSION:
        raise JavaParserProtocolError("Java parser response provenance.adapter_version did not match 0.1.0.")
    for field in ("relative_path", "source_sha256", "source_byte_length"):
        if field not in response_json:
            raise JavaParserProtocolError(f"Java parser response missing required field: {field}.")


def _verify_source_ranges(value: Any, source_length: int) -> None:
    seen: set[int] = set()

    def visit(node: Any) -> None:
        node_id = id(node)
        if node_id in seen:
            return
        seen.add(node_id)
        if isinstance(node, BaseModel):
            if all(hasattr(node, field) for field in ("start_byte", "end_byte", "status")) and getattr(
                node, "status"
            ) == "verified":
                start = getattr(node, "start_byte")
                end = getattr(node, "end_byte")
                if not (0 <= start <= end <= source_length):
                    raise JavaParserProtocolError("Java parser response contains verified range outside source bytes.")
            for child in node.__dict__.values():
                visit(child)
        elif isinstance(node, dict):
            for child in node.values():
                visit(child)
        elif isinstance(node, (tuple, list, set, frozenset)):
            for child in node:
                visit(child)

    visit(value)
