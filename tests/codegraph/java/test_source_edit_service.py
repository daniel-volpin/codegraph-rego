from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

from codegraph.config import Settings
from codegraph.java.service import JavaParserService


def _settings(tmp_path: Path) -> Settings:
    jar = tmp_path / "parser.jar"
    jar.write_bytes(b"jar")
    return Settings(
        _env_file=None,
        java_parser_jar=jar,
        java_parser_timeout_seconds=2,
        java_parser_queue_timeout_seconds=0.2,
        java_parser_heap_mb=256,
        java_parser_max_source_bytes=1024 * 1024,
        java_parser_max_output_bytes=1024 * 1024,
    )


def test_ensure_import_uses_shared_adapter_invocation(tmp_path: Path, monkeypatch) -> None:
    source = b"class Example {}\n"
    rewritten = b"import java.util.List;\nclass Example {}\n"
    service = JavaParserService(_settings(tmp_path))
    captured: dict[str, object] = {}

    def fake_invoke_process(request_bytes: bytes, *, command: tuple[str, ...]):
        request = json.loads(request_bytes)
        captured["command"] = command
        captured["request"] = request
        response = {
            "schema_version": "codegraph-java-edit/v1",
            "operation": "ensure_import",
            "status": "APPLIED",
            "relative_path": request["relative_path"],
            "qualified_name": request["qualified_name"],
            "is_static": request["is_static"],
            "on_demand": request["on_demand"],
            "source_sha256_before": hashlib.sha256(source).hexdigest(),
            "source_sha256_after": hashlib.sha256(rewritten).hexdigest(),
            "source_byte_length": len(rewritten),
            "source_base64": base64.b64encode(rewritten).decode("ascii"),
            "reason": "import_added",
            "errors": [],
        }
        return json.dumps(response).encode(), b"", 0

    monkeypatch.setattr(service, "_invoke_process", fake_invoke_process)

    result = service.ensure_import(
        source,
        relative_path="Example.java",
        qualified_name="java.util.List",
    )

    assert captured["command"] == ("source-edit",)
    assert captured["request"] == {
        "schema_version": "codegraph-java-edit-request/v1",
        "operation": "ensure_import",
        "relative_path": "Example.java",
        "source_base64": base64.b64encode(source).decode("ascii"),
        "language_level": "25",
        "qualified_name": "java.util.List",
        "is_static": False,
        "on_demand": False,
    }
    assert result.status == "APPLIED"
    assert result.source_bytes == rewritten
