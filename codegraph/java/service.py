from __future__ import annotations

import base64
import hashlib
import json
import selectors
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from codegraph.config import Settings, get_settings
from codegraph.java.models import ParsedJavaFileDTO
from codegraph.java.service_process import (
    ADAPTER_VERSION,
    EXPECTED_BACKEND,
    JDT_BACKEND_VERSION,
    RESPONSE_SCHEMA_VERSION,
    JavaParserError,
    JavaParserInputError,
    JavaParserProtocolError,
    JavaParserTimeoutError,
    JavaParserUnavailableError,
    _child_environment,
    _collect_process_output,
    _java_parser_gate,
    _JavaParserAdmissionGate,
    _kill_and_reap,
    _stderr_excerpt,
    _verify_required_protocol_fields,
    _verify_source_ranges,
)

REQUEST_SCHEMA_VERSION = "codegraph-java-request/v1"

__all__ = [
    "ADAPTER_VERSION",
    "EXPECTED_BACKEND",
    "JDT_BACKEND_VERSION",
    "JavaParserError",
    "JavaParserInputError",
    "JavaParserProtocolError",
    "JavaParserService",
    "JavaParserTimeoutError",
    "JavaParserUnavailableError",
    "REQUEST_SCHEMA_VERSION",
    "RESPONSE_SCHEMA_VERSION",
    "_JavaParserAdmissionGate",
    "_child_environment",
    "_collect_process_output",
    "_java_parser_gate",
    "_kill_and_reap",
    "_stderr_excerpt",
    "_verify_required_protocol_fields",
    "_verify_source_ranges",
    "parse_java_source",
    "selectors",
    "subprocess",
    "time",
]


class JavaParserService:
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
        level = self._settings.java_parser_language_level if language_level is None else language_level
        if level not in {str(value) for value in range(8, 26)}:
            raise JavaParserInputError("language_level must be a Java release from 8 through 25.")
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
        request_bytes = (json.dumps(request, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")

        with _java_parser_gate.acquire(
            max_active=self._settings.java_parser_max_concurrent_requests,
            queue_timeout_seconds=self._settings.java_parser_queue_timeout_seconds,
        ):
            stdout, stderr, return_code = self._invoke_parser(request_bytes)

        if return_code != 0:
            excerpt = _stderr_excerpt(stderr)
            raise JavaParserUnavailableError(f"Java parser exited with exit code {return_code}. stderr: {excerpt}")

        parsed = self._validate_response(stdout, source, safe_relative_path)
        if parsed.provenance.language_level != level:
            raise JavaParserProtocolError("Java parser language_level did not match the request.")
        if parsed.provenance.resolution_enabled != resolve_bindings:
            raise JavaParserProtocolError("Java parser resolution_enabled did not match the request.")
        return parsed

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
        if "\x00" in relative_path:
            raise JavaParserInputError("relative_path must not contain NUL bytes.")
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

    def _invoke_parser(self, request_bytes: bytes) -> tuple[bytes, bytes, int]:
        jar = Path(self._settings.java_parser_jar)
        if not jar.is_file():
            raise JavaParserUnavailableError(
                "Java parser jar not found at "
                f"{jar}. Build it with: make java-parser-build"
            )

        java = shutil.which("java")
        if java is None:
            raise JavaParserUnavailableError("Java parser requires a 'java' executable on PATH.")

        command = [
            java,
            f"-Xmx{self._settings.java_parser_heap_mb}m",
            "-XX:ActiveProcessorCount=1",
            "-jar",
            str(jar),
        ]
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=_child_environment(),
                shell=False,
                bufsize=0,
            )
        except OSError as exc:
            raise JavaParserUnavailableError(f"Failed to start Java parser subprocess: {exc}") from exc

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
