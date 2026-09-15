"""Focused tests for JDT-backed agentic workspace import editing."""

import base64
import hashlib
from pathlib import Path
from unittest.mock import Mock, patch

from codegraph.java.edit_models import JavaSourceEditDTO
from codegraph.remediation.agentic import IsolatedWorktreeEnvironment
from codegraph.remediation.agentic.contracts import AgentToolCall
from codegraph.remediation.agentic.tools import AgentToolExecutor


def _edit_result(
    source: bytes,
    *,
    status: str,
    reason: str = "import_added",
    qualified_name: str = "java.util.List",
    is_static: bool = False,
) -> JavaSourceEditDTO:
    before = b"package demo;\n\npublic class Example {}\n"
    return JavaSourceEditDTO(
        status=status,
        relative_path="src/demo/Example.java",
        qualified_name=qualified_name,
        is_static=is_static,
        source_sha256_before=hashlib.sha256(before).hexdigest(),
        source_sha256_after=hashlib.sha256(source).hexdigest(),
        source_byte_length=len(source),
        source_base64=base64.b64encode(source).decode("ascii"),
        reason=reason,
    )


def test_ensure_import_writes_only_jdt_applied_bytes(tmp_path: Path) -> None:
    original = b"package demo;\n\npublic class Example {}\n"
    rewritten = b"package demo;\n\nimport java.util.List;\n\npublic class Example {}\n"
    src = tmp_path / "src" / "demo" / "Example.java"
    src.parent.mkdir(parents=True)
    src.write_bytes(original)

    with patch(
        "codegraph.remediation.agentic.environment.ensure_java_import",
        return_value=_edit_result(rewritten, status="APPLIED"),
    ) as mock_edit:
        with IsolatedWorktreeEnvironment(tmp_path) as env:
            result = env.ensure_import("src/demo/Example.java", "java.util.List")
            updated = env.read_file("src/demo/Example.java")

    assert result.status == "APPLIED"
    assert "import java.util.List;" in updated
    assert src.read_bytes() == original
    mock_edit.assert_called_once_with(
        original,
        relative_path="src/demo/Example.java",
        qualified_name="java.util.List",
        is_static=False,
        on_demand=False,
    )


def test_ensure_import_rejection_never_mutates_scratch_source(tmp_path: Path) -> None:
    original = b"package demo;\n\npublic class Example {}\n"
    src = tmp_path / "src" / "demo" / "Example.java"
    src.parent.mkdir(parents=True)
    src.write_bytes(original)
    rejected = _edit_result(original, status="REJECTED", reason="jdt_reparse_failed")

    with patch("codegraph.remediation.agentic.environment.ensure_java_import", return_value=rejected):
        with IsolatedWorktreeEnvironment(tmp_path) as env:
            result = env.ensure_import("src/demo/Example.java", "java.util.List")
            scratch = env.read_file("src/demo/Example.java")

    assert result.status == "REJECTED"
    assert scratch.encode() == original
    assert src.read_bytes() == original


def test_agent_tool_ensure_import_maps_semantic_kinds() -> None:
    cases = (
        ("type", "java.util.List", False),
        ("static_member", "java.util.Collections.emptyList", True),
    )

    for kind, qualified_name, is_static in cases:
        env = Mock()
        rewritten = f"import {'static ' if is_static else ''}{qualified_name};\nclass Example {{}}\n".encode()
        env.ensure_import.return_value = _edit_result(
            rewritten,
            status="APPLIED",
            qualified_name=qualified_name,
            is_static=is_static,
        )
        executor = AgentToolExecutor(env, target_rule_id="TEST-RULE")
        result = executor.execute(
            AgentToolCall(
                call_id=f"call-{kind}",
                name="ensure_import",
                arguments={
                    "relative_path": "src/demo/Example.java",
                    "kind": kind,
                    "qualified_name": qualified_name,
                },
            )
        )

        assert result.success is True
        env.ensure_import.assert_called_once_with(
            "src/demo/Example.java",
            qualified_name,
            is_static=is_static,
            on_demand=False,
        )


def test_agent_tool_ensure_import_rejects_unsupported_kind() -> None:
    env = Mock()
    executor = AgentToolExecutor(env, target_rule_id="TEST-RULE")

    result = executor.execute(
        AgentToolCall(
            call_id="call-wildcard",
            name="ensure_import",
            arguments={
                "relative_path": "src/demo/Example.java",
                "kind": "wildcard",
                "qualified_name": "java.util",
            },
        )
    )

    assert result.success is False
    assert result.error == "invalid_import_kind"
    env.ensure_import.assert_not_called()
