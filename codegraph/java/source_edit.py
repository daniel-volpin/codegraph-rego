from __future__ import annotations

import base64
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

from pydantic import ValidationError

from codegraph.config import get_settings
from codegraph.java.edit_models import JavaSourceEditDTO
from codegraph.java.service import (
    JavaParserInputError,
    JavaParserProtocolError,
    JavaParserTimeoutError,
    JavaParserUnavailableError,
    _child_environment,
    _java_parser_gate,
    _stderr_excerpt,
)

REQUEST_SCHEMA_VERSION = "codegraph-java-edit-request/v1"
EDITOR_MAIN_CLASS = "io.github.codegraph.javaparser.SourceEditMain"


def ensure_java_import(
    source_bytes: bytes,
    *,
    relative_path: str,
    qualified_name: str,
    is_static: bool = False,
    on_demand: bool = False,
    language_level: str | None = None,
) -> JavaSourceEditDTO:
    """Ensure one Java import through the authoritative JDT source editor."""
    settings = get_settings()
    source = _validate_source_bytes(source_bytes, settings.java_parser_max_source_bytes)
    safe_relative_path = _validate_relative_path(relative_path)
    if not isinstance(qualified_name, str) or not qualified_name:
        raise JavaParserInputError("qualified_name must be a non-empty string.")
    if not isinstance(is_static, bool) or not isinstance(on_demand, bool):
        raise JavaParserInputError("is_static and on_demand must be booleans.")

    level = settings.java_parser_language_level if language_level is None else language_level
    if level not in {str(value) for value in range(8, 26)}:
        raise JavaParserInputError("language_level must be a Java release from 8 through 25.")

    request = {
        "schema_version": REQUEST_SCHEMA_VERSION,
        "operation": "ensure_import",
        "relative_path": safe_relative_path,
        "source_base64": base64.b64encode(source).decode("ascii"),
        "language_level": level,
        "qualified_name": qualified_name,
        "is_static": is_static,
        "on_demand": on_demand,
    }
    request_bytes = (json.dumps(request, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")

    jar = Path(settings.java_parser_jar)
    if not jar.is_file():
        raise JavaParserUnavailableError(
            f"Java parser jar not found at {jar}. Build it with: make java-parser-build"
        )
    java = shutil.which("java")
    if java is None:
        raise JavaParserUnavailableError("Java source editor requires a 'java' executable on PATH.")

    command = [
        java,
        f"-Xmx{settings.java_parser_heap_mb}m",
        "-XX:ActiveProcessorCount=1",
        "-cp",
        str(jar),
        EDITOR_MAIN_CLASS,
    ]
    try:
        with _java_parser_gate.acquire(
            max_active=settings.java_parser_max_concurrent_requests,
            queue_timeout_seconds=settings.java_parser_queue_timeout_seconds,
        ):
            completed = subprocess.run(
                command,
                input=request_bytes,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=_child_environment(),
                timeout=settings.java_parser_timeout_seconds,
                check=False,
            )
    except subprocess.TimeoutExpired as exc:
        raise JavaParserTimeoutError(
            f"Java source editor timed out after {settings.java_parser_timeout_seconds} seconds."
        ) from exc
    except OSError as exc:
        raise JavaParserUnavailableError(f"Failed to start Java source editor subprocess: {exc}") from exc

    if completed.returncode != 0:
        raise JavaParserUnavailableError(
            "Java source editor exited with exit code "
            f"{completed.returncode}. stderr: {_stderr_excerpt(completed.stderr)}"
        )
    if len(completed.stdout) > settings.java_parser_max_output_bytes:
        raise JavaParserProtocolError(
            "Java source editor stdout exceeded java_parser_max_output_bytes "
            f"({settings.java_parser_max_output_bytes})."
        )

    try:
        result = JavaSourceEditDTO.model_validate_json(completed.stdout)
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


def _validate_source_bytes(source_bytes: bytes, max_source_bytes: int) -> bytes:
    if not isinstance(source_bytes, bytes):
        raise JavaParserInputError("source_bytes must be bytes.")
    if len(source_bytes) > max_source_bytes:
        raise JavaParserInputError(
            f"source_bytes exceeds java_parser_max_source_bytes ({len(source_bytes)} > {max_source_bytes})."
        )
    try:
        source_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise JavaParserInputError("source_bytes must be valid UTF-8.") from exc
    return source_bytes


def _validate_relative_path(relative_path: str) -> str:
    if not isinstance(relative_path, str) or "\x00" in relative_path:
        raise JavaParserInputError("relative_path must be a string without NUL bytes.")
    path = Path(relative_path)
    if path.is_absolute() or ".." in path.parts or relative_path in {"", "."}:
        raise JavaParserInputError("relative_path must be a non-absolute path without '..' segments.")
    return relative_path
