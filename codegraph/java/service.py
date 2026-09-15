from __future__ import annotations

import base64
import hashlib
import json
import os
import selectors
import shutil
import subprocess
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from threading import Condition
from typing import Any

from pydantic import BaseModel, ValidationError

from codegraph.config import Settings, get_settings
from codegraph.java.edit_models import JavaSourceEditDTO
from codegraph.java.models import ParsedJavaFileDTO

REQUEST_SCHEMA_VERSION = "codegraph-java-request/v1"
RESPONSE_SCHEMA_VERSION = "codegraph-java/v1"
EDIT_REQUEST_SCHEMA_VERSION = "codegraph-java-edit-request/v1"
SOURCE_EDIT_COMMAND = "source-edit"
EXPECTED_BACKEND = "eclipse-jdt"
JDT_BACKEND_VERSION = "3.47.0"
ADAPTER_VERSION = "0.1.0"
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


class JavaParserService:
    """Single Python boundary for all JDT adapter operations."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def parse_java_source(
        self,
        source_bytes: bytes,
        *,
        relative_path: str,
        source_roots: tuple[Path, ...] = (),
        classpath: tuple[Path, ...] = (),
        resolve_bindings: bool = True,
        language_level: str | None = None,
    ) -> ParsedJavaFileDTO:
        source = self._validate_source_bytes(source_bytes)
        safe_relative_path = self._validate_relative_path(relative_path)
        level = self._resolve_language_level(language_level)
        if not isinstance(resolve_bindings, bool):
            raise JavaParserInputError("resolve_bindings must be a boolean.")
        request = self._build_request(
            source,
            relative_path=safe_relative_path,
            source_roots=source_roots,
            classpath=classpath,
            resolve_bindings=resolve_bindings,
            language_level=level,
        )
        stdout = self._invoke_adapter(self._encode_request(request))

        parsed = self._validate_response(stdout, source, safe_relative_path)
        if parsed.provenance.language_level != level:
            raise JavaParserProtocolError("Java parser language_level did not match the request.")
        if parsed.provenance.resolution_enabled != resolve_bindings:
            raise JavaParserProtocolError("Java parser resolution_enabled did not match the request.")
        return parsed

    def ensure_import(
        self,
        source_bytes: bytes,
        *,
        relative_path: str,
        qualified_name: str,
        is_static: bool = False,
        on_demand: bool = False,
        language_level: str | None = None,
    ) -> JavaSourceEditDTO:
        """Ensure one import through the same bounded JDT process boundary used for parsing."""
        source = self._validate_source_bytes(source_bytes)
        safe_relative_path = self._validate_relative_path(relative_path)
        level = self._resolve_language_level(language_level)
        if not isinstance(qualified_name, str) or not qualified_name:
            raise JavaParserInputError("qualified_name must be a non-empty string.")
        if not isinstance(is_static, bool) or not isinstance(on_demand, bool):
            raise JavaParserInputError("is_static and on_demand must be booleans.")

        request = {
            "schema_version": EDIT_REQUEST_SCHEMA_VERSION,
            "operation": "ensure_import",
            "relative_path": safe_relative_path,
            "source_base64": base64.b64encode(source).decode("ascii"),
            "language_level": level,
            "qualified_name": qualified_name,
            "is_static": is_static,
            "on_demand": on_demand,
        }
        stdout = self._invoke_adapter(self._encode_request(request), command=(SOURCE_EDIT_COMMAND,))

        try:
            result = JavaSourceEditDTO.model_validate_json(stdout)
        except ValidationError as exc:
            issues = "; ".join(
                f"{'.'.join(map(str, issue['loc'])) or '<root>'}: {issue['type']}"
                for issue in exc.errors(include_input=False, include_context=False)[:5]
            )
            raise JavaParserProtocolError(f"Java source editor returned invalid JSON: {issues}") from exc

        expected_before = hashlib.sha256(source).hexdigest()
        if result.relative_path != safe_relative_path:
            raise JavaParserProtocolError("Java source editor relative_path did not match the request.")
        if result.qualified_name != qualified_name:
            raise JavaParserProtocolError("Java source editor qualified_name did not match the request.")
        if result.is_static != is_static or result.on_demand != on_demand:
            raise JavaParserProtocolError("Java source editor import flags did not match the request.")
        if result.source_sha256_before != expected_before:
            raise JavaParserProtocolError("Java source editor source_sha256_before did not match the request bytes.")
        return result

    def _resolve_language_level(self, language_level: str | None) -> str:
        level = self._settings.java_parser_language_level if language_level is None else language_level
        if level not in {str(value) for value in range(8, 26)}:
            raise JavaParserInputError("language_level must be a Java release from 8 through 25.")
        return level

    def _validate_source_bytes(self, source_bytes: bytes) -> bytes:
        if not isinstance(source_bytes, bytes):
            raise JavaParserInputError("source_bytes must be bytes.")
        if len(source_bytes) > self._settings.java_parser_max_source_bytes:
            raise JavaParserInputError(
                "source_bytes exceeds java_parser_max_source_bytes "
                f"({len(source_bytes)} > {self._settings.java_parser_max_source_bytes})."
            )
        try:
            source_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise JavaParserInputError("source_bytes must be valid UTF-8.") from exc
        return source_bytes

    def _validate_relative_path(self, relative_path: str) -> str:
        if not isinstance(relative_path, str) or "\x00" in relative_path:
            raise JavaParserInputError("relative_path must be a string without NUL bytes.")
        path = Path(relative_path)
        if path.is_absolute() or ".." in path.parts or relative_path in {"", "."}:
            raise JavaParserInputError("relative_path must be a non-absolute path without '..' segments.")
        return relative_path

    def _build_request(
        self,
        source: bytes,
        *,
        relative_path: str,
        source_roots: tuple[Path, ...],
        classpath: tuple[Path, ...],
        resolve_bindings: bool,
        language_level: str,
    ) -> dict[str, Any]:
        return {
            "schema_version": REQUEST_SCHEMA_VERSION,
            "relative_path": relative_path,
            "source_base64": base64.b64encode(source).decode("ascii"),
            "language_level": language_level,
            "resolve_bindings": resolve_bindings,
            "classpath": [path.as_posix() for path in self._validate_classpath(classpath)],
            "source_roots": [path.as_posix() for path in self._validate_source_roots(source_roots)],
        }

    def _validate_source_roots(self, source_roots: tuple[Path, ...]) -> tuple[Path, ...]:
        resolved: list[Path] = []
        for root in source_roots:
            path = Path(root).expanduser()
            if not path.exists() or not path.is_dir():
                raise JavaParserInputError(f"source_roots entry must be an existing directory: {path}")
            resolved.append(path.resolve())
        return tuple(resolved)

    def _validate_classpath(self, classpath: tuple[Path, ...]) -> tuple[Path, ...]:
        resolved: list[Path] = []
        for entry in classpath:
            path = Path(entry).expanduser()
            if not path.exists():
                raise JavaParserInputError(f"classpath entry does not exist: {path}")
            if not (path.is_dir() or (path.is_file() and path.suffix == ".jar")):
                raise JavaParserInputError(f"classpath entry must be a directory or .jar file: {path}")
            resolved.append(path.resolve())
        return tuple(resolved)

    @staticmethod
    def _encode_request(request: dict[str, Any]) -> bytes:
        return (json.dumps(request, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")

    def _invoke_adapter(self, request_bytes: bytes, *, command: tuple[str, ...] = ()) -> bytes:
        with _java_parser_gate.acquire(
            max_active=self._settings.java_parser_max_concurrent_requests,
            queue_timeout_seconds=self._settings.java_parser_queue_timeout_seconds,
        ):
            stdout, stderr, return_code = self._invoke_process(request_bytes, command=command)

        if return_code != 0:
            excerpt = _stderr_excerpt(stderr)
            raise JavaParserUnavailableError(
                f"Java JDT adapter exited with exit code {return_code}. stderr: {excerpt}"
            )
        return stdout

    def _invoke_process(self, request_bytes: bytes, *, command: tuple[str, ...]) -> tuple[bytes, bytes, int]:
        jar = Path(self._settings.java_parser_jar)
        if not jar.is_file():
            raise JavaParserUnavailableError(
                "Java parser jar not found at "
                f"{jar}. Build it with: make java-parser-build"
            )

        java = shutil.which("java")
        if java is None:
            raise JavaParserUnavailableError("Java JDT adapter requires a 'java' executable on PATH.")

        process_command = [
            java,
            f"-Xmx{self._settings.java_parser_heap_mb}m",
            "-XX:ActiveProcessorCount=1",
            "-jar",
            str(jar),
            *command,
        ]
        try:
            process = subprocess.Popen(
                process_command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=_child_environment(),
                shell=False,
                bufsize=0,
            )
        except OSError as exc:
            raise JavaParserUnavailableError(f"Failed to start Java JDT adapter subprocess: {exc}") from exc

        try:
            return _collect_process_output(
                process,
                request_bytes,
                timeout_seconds=self._settings.java_parser_timeout_seconds,
                max_stdout_bytes=self._settings.java_parser_max_output_bytes,
            )
        finally:
            try:
                _kill_and_reap(process)
            finally:
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream is not None:
                        stream.close()

    def _validate_response(self, stdout: bytes, source: bytes, relative_path: str) -> ParsedJavaFileDTO:
        try:
            response_text = stdout.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise JavaParserProtocolError("Java parser stdout was not valid UTF-8 JSON.") from exc
        try:
            response_json = json.loads(response_text)
            _verify_required_protocol_fields(response_json)

            parsed = ParsedJavaFileDTO.model_validate_json(response_text)
        except ValidationError as exc:
            issues = "; ".join(
                f"{'.'.join(map(str, issue['loc'])) or '<root>'}: {issue['type']}"
                for issue in exc.errors(include_input=False, include_context=False)[:5]
            )
            raise JavaParserProtocolError(f"Java parser returned invalid ParsedJavaFileDTO JSON: {issues}") from exc
        except json.JSONDecodeError as exc:
            raise JavaParserProtocolError(f"Java parser stdout was not valid JSON: {exc}") from exc

        expected_hash = hashlib.sha256(source).hexdigest()
        if parsed.schema_version != RESPONSE_SCHEMA_VERSION:
            raise JavaParserProtocolError("Java parser response schema_version did not match codegraph-java/v1.")
        if parsed.relative_path != relative_path:
            raise JavaParserProtocolError("Java parser response relative_path did not match the request.")
        if parsed.source_sha256 != expected_hash:
            raise JavaParserProtocolError("Java parser response source_sha256 did not match the request bytes.")
        if parsed.source_byte_length != len(source):
            raise JavaParserProtocolError("Java parser response source_byte_length did not match the request bytes.")
        provenance = parsed.provenance
        if provenance.backend != EXPECTED_BACKEND:
            raise JavaParserProtocolError("Java parser response provenance.backend did not match eclipse-jdt.")
        if provenance.backend_version != JDT_BACKEND_VERSION:
            raise JavaParserProtocolError("Java parser response provenance.backend_version did not match 3.47.0.")
        if provenance.adapter_version != ADAPTER_VERSION:
            raise JavaParserProtocolError("Java parser response provenance.adapter_version did not match 0.1.0.")
        _verify_source_ranges(parsed, len(source))
        return parsed


def parse_java_source(
    source_bytes: bytes,
    *,
    relative_path: str,
    source_roots: tuple[Path, ...] = (),
    classpath: tuple[Path, ...] = (),
    resolve_bindings: bool = True,
    language_level: str | None = None,
) -> ParsedJavaFileDTO:
    return JavaParserService(get_settings()).parse_java_source(
        source_bytes,
        relative_path=relative_path,
        source_roots=source_roots,
        classpath=classpath,
        resolve_bindings=resolve_bindings,
        language_level=language_level,
    )


def ensure_java_import(
    source_bytes: bytes,
    *,
    relative_path: str,
    qualified_name: str,
    is_static: bool = False,
    on_demand: bool = False,
    language_level: str | None = None,
) -> JavaSourceEditDTO:
    return JavaParserService(get_settings()).ensure_import(
        source_bytes,
        relative_path=relative_path,
        qualified_name=qualified_name,
        is_static=is_static,
        on_demand=on_demand,
        language_level=language_level,
    )


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
