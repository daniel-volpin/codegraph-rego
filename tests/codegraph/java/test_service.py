from __future__ import annotations

import base64
import hashlib
import json
import stat
import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path

import pytest

from codegraph.config import Settings
from codegraph.java import service as java_service
from codegraph.java.service import (
    JavaParserInputError,
    JavaParserProtocolError,
    JavaParserService,
    JavaParserTimeoutError,
    JavaParserUnavailableError,
    parse_java_source,
)


@pytest.fixture
def scratch(tmp_path: Path) -> Path:
    return tmp_path


def make_settings(scratch: Path, **overrides: object) -> Settings:
    jar = scratch / "parser.jar"
    jar.write_bytes(b"jar")
    values: dict[str, object] = {
        "_env_file": None,
        "java_parser_jar": jar,
        "java_parser_timeout_seconds": 2,
        "java_parser_queue_timeout_seconds": 0.2,
        "java_parser_heap_mb": 256,
        "java_parser_max_source_bytes": 1024 * 1024,
        "java_parser_max_output_bytes": 1024 * 1024,
    }
    values.update(overrides)
    return Settings(**values)


def install_fake_java(scratch: Path, body: str, monkeypatch: pytest.MonkeyPatch) -> Path:
    java_bin = scratch / "bin"
    java_bin.mkdir()
    java = java_bin / "java"
    java.write_text(f"#!{sys.executable}\n" + textwrap.dedent(body), encoding="utf-8")
    java.chmod(java.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", java_bin.as_posix())
    return java


SUCCESS_FAKE_JAVA = r"""
import base64
import hashlib
import json
import os
import sys

request = json.loads(sys.stdin.read())
source = base64.b64decode(request["source_base64"])
assert sys.argv[1].startswith("-Xmx")
assert "-XX:ActiveProcessorCount=1" in sys.argv
assert "-jar" in sys.argv
assert "JAVA_TOOL_OPTIONS" not in os.environ
assert "JDK_JAVA_OPTIONS" not in os.environ
assert "LLM_API_KEY" not in os.environ
assert "OPENAI_API_KEY" not in os.environ
assert "OTEL_PYTHON_AUTO_INSTRUMENTATION_ENABLED" not in os.environ
response = {
    "schema_version": "codegraph-java/v1",
    "provenance": {
        "backend": "eclipse-jdt",
        "backend_version": "3.47.0",
        "adapter_version": "0.1.0",
        "language_level": request["language_level"],
        "resolution_enabled": request["resolve_bindings"],
    },
    "relative_path": request["relative_path"],
    "package_name": None,
    "imports": [],
    "source_sha256": hashlib.sha256(source).hexdigest(),
    "source_byte_length": len(source),
    "coverage": "complete",
    "diagnostics": [],
    "types": [],
    "fields": [],
    "methods": [],
}
print(json.dumps(response))
"""


def test_parse_java_source_sends_canonical_request_and_validates_dto(
    scratch: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    capture = scratch / "capture.json"
    install_fake_java(
        scratch,
        SUCCESS_FAKE_JAVA
        + f"""
with open({str(capture)!r}, "w", encoding="utf-8") as handle:
    json.dump({{"argv": sys.argv, "request": request}}, handle)
""",
        monkeypatch,
    )
    source_root = scratch / "src"
    source_root.mkdir()
    classpath_jar = scratch / "lib.jar"
    classpath_jar.write_bytes(b"jar")
    monkeypatch.setenv("JAVA_TOOL_OPTIONS", "-agentlib:forbidden")
    monkeypatch.setenv("LLM_API_KEY", "secret")
    monkeypatch.setenv("OPENAI_API_KEY", "secret")
    monkeypatch.setenv("OTEL_PYTHON_AUTO_INSTRUMENTATION_ENABLED", "1")

    parsed = JavaParserService(make_settings(scratch)).parse_java_source(
        b"class A {}\n",
        relative_path="src/A.java",
        source_roots=(source_root,),
        classpath=(classpath_jar,),
        language_level=None,
    )

    captured = json.loads(capture.read_text(encoding="utf-8"))
    request = captured["request"]
    assert parsed.relative_path == "src/A.java"
    assert parsed.source_byte_length == len(b"class A {}\n")
    assert request == {
        "schema_version": "codegraph-java-request/v1",
        "relative_path": "src/A.java",
        "source_base64": base64.b64encode(b"class A {}\n").decode("ascii"),
        "language_level": "25",
        "resolve_bindings": True,
        "classpath": [classpath_jar.resolve().as_posix()],
        "source_roots": [source_root.resolve().as_posix()],
    }
    assert captured["argv"][1] == "-Xmx256m"


@pytest.mark.parametrize(
    ("source", "relative_path", "message"),
    [
        (b"\xff", "A.java", "UTF-8"),
        (b"class A {}", "/abs/A.java", "relative_path"),
        (b"class A {}", "../A.java", "relative_path"),
        (b"class A {}", "bad\x00.java", "relative_path"),
    ],
)
def test_input_validation_rejects_invalid_source_and_relative_paths(
    scratch: Path, source: bytes, relative_path: str, message: str
) -> None:
    with pytest.raises(JavaParserInputError, match=message):
        JavaParserService(make_settings(scratch)).parse_java_source(source, relative_path=relative_path)


def test_input_validation_rejects_oversize_source(scratch: Path) -> None:
    with pytest.raises(JavaParserInputError, match="exceeds"):
        JavaParserService(make_settings(scratch, java_parser_max_source_bytes=1024 * 1024)).parse_java_source(
            b"a" * ((1024 * 1024) + 1), relative_path="A.java"
        )


def test_input_validation_requires_existing_explicit_paths(scratch: Path) -> None:
    settings = make_settings(scratch)
    with pytest.raises(JavaParserInputError, match="source_roots"):
        JavaParserService(settings).parse_java_source(
            b"class A {}", relative_path="A.java", source_roots=(scratch / "missing",)
        )
    bad_classpath = scratch / "lib.txt"
    bad_classpath.write_text("not a jar", encoding="utf-8")
    with pytest.raises(JavaParserInputError, match="classpath"):
        JavaParserService(settings).parse_java_source(b"class A {}", relative_path="A.java", classpath=(bad_classpath,))


def test_missing_jar_fails_with_actionable_build_command(scratch: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    install_fake_java(scratch, SUCCESS_FAKE_JAVA, monkeypatch)
    settings = make_settings(scratch, java_parser_jar=scratch / "missing.jar")

    with pytest.raises(JavaParserUnavailableError, match="make java-parser-build"):
        JavaParserService(settings).parse_java_source(b"class A {}", relative_path="A.java")


def test_missing_java_binary_fails_before_launch(scratch: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATH", "")

    with pytest.raises(JavaParserUnavailableError, match="java"):
        JavaParserService(make_settings(scratch)).parse_java_source(b"class A {}", relative_path="A.java")


def test_nonzero_exit_reports_bounded_stderr_without_source(scratch: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    install_fake_java(
        scratch,
        """
import sys
sys.stderr.write("boom " * 10000)
sys.exit(7)
""",
        monkeypatch,
    )

    with pytest.raises(JavaParserUnavailableError) as exc_info:
        JavaParserService(make_settings(scratch)).parse_java_source(b"class Secret {}", relative_path="A.java")

    message = str(exc_info.value)
    assert "exit code 7" in message
    assert "Secret" not in message
    assert len(message) < 5000


@pytest.mark.parametrize(
    ("body", "error", "match"),
    [
        ("import sys\nsys.stdout.write('{')\n", JavaParserProtocolError, "JSON"),
        ("import sys\nsys.stdout.write('x' * (1024 * 1024 + 1))\n", JavaParserProtocolError, "exceeded"),
    ],
)
def test_protocol_errors_cover_malformed_and_oversize_stdout(
    scratch: Path, monkeypatch: pytest.MonkeyPatch, body: str, error: type[Exception], match: str
) -> None:
    install_fake_java(scratch, body, monkeypatch)

    with pytest.raises(error, match=match):
        JavaParserService(make_settings(scratch)).parse_java_source(b"class A {}", relative_path="A.java")


def test_protocol_error_on_source_hash_mismatch(scratch: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    install_fake_java(
        scratch,
        r"""
import base64
import json
import sys
request = json.loads(sys.stdin.read())
source = base64.b64decode(request["source_base64"])
print(json.dumps({
    "schema_version": "codegraph-java/v1",
    "provenance": {"backend": "eclipse-jdt", "backend_version": "3.47.0", "adapter_version": "0.1.0"},
    "relative_path": request["relative_path"],
    "source_sha256": "0" * 64,
    "source_byte_length": len(source),
    "coverage": "complete",
}))
""",
        monkeypatch,
    )

    with pytest.raises(JavaParserProtocolError, match="source_sha256"):
        JavaParserService(make_settings(scratch)).parse_java_source(b"class A {}", relative_path="A.java")


@pytest.mark.parametrize(
    ("response_update", "match"),
    [
        ({"schema_version": "legacy-java/v0"}, "schema_version"),
        ({"provenance": {"backend_version": "3.47.0", "adapter_version": "0.1.0"}}, "provenance.backend"),
        (
            {"provenance": {"backend": "javalang", "backend_version": "3.47.0", "adapter_version": "0.1.0"}},
            "provenance.backend",
        ),
        (
            {"provenance": {"backend": "eclipse-jdt", "backend_version": "3.47.0", "adapter_version": "legacy"}},
            "provenance.adapter_version",
        ),
        ({"relative_path": "Other.java"}, "relative_path"),
    ],
)
def test_protocol_validation_refuses_legacy_or_defaulted_response_fields(
    scratch: Path, monkeypatch: pytest.MonkeyPatch, response_update: dict[str, object], match: str
) -> None:
    install_fake_java(
        scratch,
        f"""
import base64
import hashlib
import json
import sys
request = json.loads(sys.stdin.read())
source = base64.b64decode(request["source_base64"])
response = {{
    "schema_version": "codegraph-java/v1",
    "provenance": {{"backend": "eclipse-jdt", "backend_version": "3.47.0", "adapter_version": "0.1.0"}},
    "relative_path": request["relative_path"],
    "source_sha256": hashlib.sha256(source).hexdigest(),
    "source_byte_length": len(source),
    "coverage": "complete",
}}
response.update({response_update!r})
print(json.dumps(response))
""",
        monkeypatch,
    )

    with pytest.raises(JavaParserProtocolError, match=match):
        JavaParserService(make_settings(scratch)).parse_java_source(b"class A {}", relative_path="A.java")


def test_timeout_kills_and_reaps_child(scratch: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    install_fake_java(
        scratch,
        """
import time
time.sleep(10)
""",
        monkeypatch,
    )

    with pytest.raises(JavaParserTimeoutError):
        JavaParserService(make_settings(scratch, java_parser_timeout_seconds=0.1)).parse_java_source(
            b"class A {}", relative_path="A.java"
        )


def test_cross_instance_gate_expires_queued_request(scratch: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    install_fake_java(
        scratch,
        """
import time
time.sleep(0.4)
""",
        monkeypatch,
    )
    settings = make_settings(
        scratch, java_parser_timeout_seconds=2, java_parser_queue_timeout_seconds=0.05, java_parser_max_concurrent_requests=1
    )
    first_error: list[BaseException] = []

    def run_first() -> None:
        try:
            JavaParserService(settings).parse_java_source(b"class A {}", relative_path="A.java")
        except BaseException as exc:
            first_error.append(exc)

    thread = threading.Thread(
        target=run_first,
        daemon=True,
    )
    thread.start()
    time.sleep(0.1)

    with pytest.raises(JavaParserUnavailableError, match="queue"):
        JavaParserService(settings).parse_java_source(b"class B {}", relative_path="B.java")

    thread.join(timeout=2)
    assert isinstance(first_error[0], JavaParserProtocolError)


def test_public_function_uses_settings_and_returns_dto(scratch: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    install_fake_java(scratch, SUCCESS_FAKE_JAVA, monkeypatch)
    from codegraph import config

    monkeypatch.setattr(config, "get_settings", lambda: make_settings(scratch))

    parsed = parse_java_source(b"class A {}", relative_path="A.java")

    assert parsed.source_sha256 == hashlib.sha256(b"class A {}").hexdigest()


def test_expired_waiter_cannot_take_newly_released_parser_slot(monkeypatch: pytest.MonkeyPatch) -> None:
    gate = java_service._JavaParserAdmissionGate()
    active = threading.Event()
    release_active = threading.Event()
    waiting = threading.Event()
    now = 0.0
    errors: list[JavaParserUnavailableError] = []
    admitted: list[bool] = []
    original_wait = gate._condition.wait

    def observed_wait(timeout: float | None = None) -> bool:
        waiting.set()
        return original_wait(timeout)

    monkeypatch.setattr(java_service.time, "monotonic", lambda: now)
    monkeypatch.setattr(gate._condition, "wait", observed_wait)

    def hold_slot() -> None:
        with gate.acquire(max_active=1, queue_timeout_seconds=5):
            active.set()
            release_active.wait(timeout=2)

    def wait_for_slot() -> None:
        try:
            with gate.acquire(max_active=1, queue_timeout_seconds=5):
                admitted.append(True)
        except JavaParserUnavailableError as exc:
            errors.append(exc)

    holder = threading.Thread(target=hold_slot)
    waiter = threading.Thread(target=wait_for_slot)
    holder.start()
    try:
        assert active.wait(timeout=2)
        waiter.start()
        assert waiting.wait(timeout=2)
        now = 6.0
    finally:
        release_active.set()
        holder.join(timeout=2)
        if waiter.ident is not None:
            waiter.join(timeout=2)

    assert not holder.is_alive()
    assert not waiter.is_alive()
    assert not admitted
    assert len(errors) == 1
    assert "timed out" in str(errors[0])
    with gate.acquire(max_active=1, queue_timeout_seconds=5):
        pass


@pytest.mark.parametrize("cancel", [False, True])
def test_child_and_pipes_are_closed_on_success_or_cancellation(scratch, monkeypatch, cancel) -> None:
    install_fake_java(scratch, SUCCESS_FAKE_JAVA, monkeypatch)
    children = []
    real_popen = subprocess.Popen

    def capture_child(*args, **kwargs):
        child = real_popen(*args, **kwargs)
        children.append(child)
        return child

    monkeypatch.setattr(java_service.subprocess, "Popen", capture_child)
    if cancel:
        def interrupt(*args, **kwargs):
            raise KeyboardInterrupt("cancel parser")

        monkeypatch.setattr(java_service.selectors.DefaultSelector, "select", interrupt)
        with pytest.raises(KeyboardInterrupt, match="cancel parser"):
            JavaParserService(make_settings(scratch)).parse_java_source(b"class A {}", relative_path="A.java")
    else:
        JavaParserService(make_settings(scratch)).parse_java_source(b"class A {}", relative_path="A.java")

    assert len(children) == 1
    assert children[0].poll() is not None
    assert all(stream.closed for stream in (children[0].stdin, children[0].stdout, children[0].stderr))


@pytest.mark.parametrize("override", ['response["provenance"]["language_level"] = "8"',
                                   'response["provenance"]["resolution_enabled"] = False'])
def test_response_cannot_silently_change_requested_analysis(scratch, monkeypatch, override) -> None:
    body = SUCCESS_FAKE_JAVA.replace("print(json.dumps(response))", override + "\nprint(json.dumps(response))")
    install_fake_java(scratch, body, monkeypatch)
    with pytest.raises(JavaParserProtocolError, match="request"):
        JavaParserService(make_settings(scratch)).parse_java_source(b"class A {}", relative_path="A.java")


@pytest.mark.parametrize("level", ["", "latest", "99"])
def test_invalid_language_level_refuses_before_launch(scratch, level) -> None:
    with pytest.raises(JavaParserInputError, match="language_level"):
        JavaParserService(make_settings(scratch)).parse_java_source(
            b"class A {}", relative_path="A.java", language_level=level
        )
