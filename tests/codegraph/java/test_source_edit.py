import base64
import json
import subprocess
from pathlib import Path

import pytest

from codegraph.config import settings
from codegraph.java.edit_models import JavaSourceEditDTO

ROOT = Path(__file__).resolve().parents[3]
JAR = settings.java_parser_jar


@pytest.fixture(autouse=True)
def require_prebuilt_parser() -> None:
    if not JAR.is_file():
        pytest.fail(f"JDT parser jar is missing at {JAR}; run `make java-parser-build` before these tests.")


def run_editor(
    source: bytes,
    qualified_name: str,
    *,
    relative_path: str = "src/main/java/demo/Example.java",
    is_static: bool = False,
    on_demand: bool = False,
) -> JavaSourceEditDTO:
    request = {
        "schema_version": "codegraph-java-edit-request/v1",
        "operation": "ensure_import",
        "relative_path": relative_path,
        "source_base64": base64.b64encode(source).decode("ascii"),
        "language_level": "25",
        "qualified_name": qualified_name,
        "is_static": is_static,
        "on_demand": on_demand,
    }
    completed = subprocess.run(
        [
            "java",
            "-XX:ActiveProcessorCount=1",
            "-Xmx768m",
            "-jar",
            str(JAR),
            "source-edit",
        ],
        input=json.dumps(request),
        text=True,
        capture_output=True,
        cwd=ROOT,
        timeout=20,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stderr == ""
    return JavaSourceEditDTO.model_validate_json(completed.stdout)


def test_ensure_import_uses_ast_rewrite_and_preserves_surrounding_source() -> None:
    source = b"package demo;\n\n// keep this comment\npublic class Example {}\n"

    result = run_editor(source, "java.util.List")

    assert result.status == "APPLIED"
    rewritten = result.source_bytes.decode()
    assert "import java.util.List;" in rewritten
    assert "// keep this comment" in rewritten
    assert "public class Example {}" in rewritten


def test_ensure_import_is_idempotent() -> None:
    source = b"package demo;\n\nimport java.util.List;\n\npublic class Example {}\n"

    result = run_editor(source, "java.util.List")

    assert result.status == "UNCHANGED"
    assert result.source_bytes == source
    assert result.reason == "import_already_present"


def test_ensure_import_supports_static_and_on_demand_forms() -> None:
    static_result = run_editor(
        b"class Example {}\n",
        "java.util.Collections.emptyList",
        relative_path="Example.java",
        is_static=True,
    )
    wildcard_result = run_editor(
        b"class Example {}\n",
        "java.util",
        relative_path="Example.java",
        on_demand=True,
    )

    assert static_result.status == "APPLIED"
    assert "import static java.util.Collections.emptyList;" in static_result.source_bytes.decode()
    assert wildcard_result.status == "APPLIED"
    assert "import java.util.*;" in wildcard_result.source_bytes.decode()


def test_ensure_import_does_not_implement_custom_name_resolution() -> None:
    source = b"package demo;\n\nimport java.awt.List;\n\npublic class Example {}\n"

    result = run_editor(source, "java.util.List")

    assert result.reason not in {"simple_name_conflict", "declared_type_conflict"}
    if result.status == "REJECTED":
        assert result.reason == "jdt_reparse_failed"
        assert result.source_bytes == source
    else:
        assert result.status == "APPLIED"
        assert "import java.util.List;" in result.source_bytes.decode()


def test_ensure_import_rejects_invalid_source_without_mutation() -> None:
    source = b"package demo; public class Example {\n"

    result = run_editor(source, "java.util.List")

    assert result.status == "REJECTED"
    assert result.reason == "source_not_editable"
    assert result.source_bytes == source
    assert result.errors


def test_ensure_import_rejects_invalid_qualified_name_without_mutation() -> None:
    source = b"class Example {}\n"

    result = run_editor(source, "import java.util.List;")

    assert result.status == "REJECTED"
    assert result.reason == "invalid_import_name"
    assert result.source_bytes == source
