"""Unit and integration tests for autonomous agentic remediation."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from codegraph.ingestion.snapshots import create_source_snapshot_from_bytes, sha256_hex
from codegraph.remediation.agentic import (
    AgenticRemediationService,
    IsolatedWorktreeEnvironment,
)
from codegraph.remediation.agentic.contracts import AgentVerificationStatus

SAMPLE_JAVA = """package demo;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

public class SqlDemo {
    public void queryUser(Connection conn, String userId) throws Exception {
        Statement stmt = conn.createStatement();
        String sql = "SELECT * FROM users WHERE id = '" + userId + "'";
        ResultSet rs = stmt.executeQuery(sql);
    }
}
"""


def _verification(*, compile_passed: bool = True) -> AgentVerificationStatus:
    return AgentVerificationStatus(
        compile_passed=compile_passed,
        compile_output="ok" if compile_passed else "compile failed",
        tests_passed=True,
        test_output="ok",
        policy_passed=True,
        policy_findings=[],
        remaining_violations=[],
    )


def test_isolated_worktree_environment_sandboxes_edits(tmp_path: Path) -> None:
    src = tmp_path / "src" / "demo" / "SqlDemo.java"
    src.parent.mkdir(parents=True)
    src.write_text(SAMPLE_JAVA, encoding="utf-8")

    with IsolatedWorktreeEnvironment(tmp_path) as env:
        content = env.read_file("src/demo/SqlDemo.java")
        assert "SELECT * FROM users" in content

        # Apply edit in scratch
        ok = env.apply_replacement(
            "src/demo/SqlDemo.java",
            "String sql = \"SELECT * FROM users WHERE id = '\" + userId + \"'\";",
            "String sql = \"SELECT * FROM users WHERE id = ?\";",
        )
        assert ok is True
        env.add_import("src/demo/SqlDemo.java", "import java.sql.PreparedStatement;")

        modified = env.get_modified_files()
        assert modified == ["src/demo/SqlDemo.java"]
        diff = env.compute_unified_diff()
        assert "+import java.sql.PreparedStatement;" in diff

    # Verify original file is 100% untouched
    assert src.read_text(encoding="utf-8") == SAMPLE_JAVA


def test_agentic_multi_turn_remediation_sql_injection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    src = tmp_path / "src" / "demo" / "SqlDemo.java"
    src.parent.mkdir(parents=True)
    src.write_text(SAMPLE_JAVA, encoding="utf-8")

    finding = {
        "violation_id": "ISO-A.8-SQL-INJECTION",
        "method_key": "ws@rev:src/demo/SqlDemo.java#method:queryUser",
        "target_method": "demo.SqlDemo.queryUser(Connection, String)",
        "file_path": src.as_posix(),
        "reason": "SQL injection detected in string concatenation",
        "code_snippet": SAMPLE_JAVA,
    }

    turn_counter = 0

    def mock_llm_client(messages, tools=None, **kwargs):
        nonlocal turn_counter
        turn_counter += 1

        if turn_counter == 1:
            # Turn 1: Add import and edit file
            return {
                "choices": [
                    {
                        "message": {
                            "content": "I will add the PreparedStatement import and refactor the method to use parameter binding.",
                            "tool_calls": [
                                {
                                    "id": "call_1",
                                    "function": {
                                        "name": "add_import",
                                        "arguments": json.dumps({
                                            "relative_path": "src/demo/SqlDemo.java",
                                            "import_statement": "import java.sql.PreparedStatement;",
                                        }),
                                    },
                                },
                                {
                                    "id": "call_2",
                                    "function": {
                                        "name": "edit_file",
                                        "arguments": json.dumps({
                                            "relative_path": "src/demo/SqlDemo.java",
                                            "old_str": (
                                                "        Statement stmt = conn.createStatement();\n"
                                                "        String sql = \"SELECT * FROM users WHERE id = '\" + userId + \"'\";\n"
                                                "        ResultSet rs = stmt.executeQuery(sql);"
                                            ),
                                            "new_str": (
                                                "        String sql = \"SELECT * FROM users WHERE id = ?\";\n"
                                                "        PreparedStatement stmt = conn.prepareStatement(sql);\n"
                                                "        stmt.setString(1, userId);\n"
                                                "        ResultSet rs = stmt.executeQuery();"
                                            ),
                                        }),
                                    },
                                },
                            ],
                        }
                    }
                ]
            }

        elif turn_counter == 2:
            # Turn 2: Run verification
            return {
                "choices": [
                    {
                        "message": {
                            "content": "Running verification on the updated workspace.",
                            "tool_calls": [
                                {
                                    "id": "call_3",
                                    "function": {
                                        "name": "run_verification",
                                        "arguments": "{}",
                                    },
                                }
                            ],
                        }
                    }
                ]
            }

        else:
            # Turn 3: Conclude remediation
            return {
                "choices": [
                    {
                        "message": {
                            "content": "Verification passed. Submitting patch.",
                            "tool_calls": [
                                {
                                    "id": "call_4",
                                    "function": {
                                        "name": "finish_remediation",
                                        "arguments": json.dumps({
                                            "reason": "Parameterized SQL query using PreparedStatement with typed parameter index binding.",
                                        }),
                                    },
                                }
                            ],
                        }
                    }
                ]
            }

    monkeypatch.setattr(IsolatedWorktreeEnvironment, "run_full_verification", lambda *_args: _verification())
    service = AgenticRemediationService(llm_client=mock_llm_client)
    result = service.remediate_finding(finding, workspace_root=tmp_path, max_turns=5)

    assert result.status == "SUCCESS"
    assert "PreparedStatement" in result.diff
    assert "stmt.setString(1, userId)" in result.diff
    assert result.modified_files == ["src/demo/SqlDemo.java"]
    assert "Parameterized SQL query" in result.reason
    assert src.read_text(encoding="utf-8") == SAMPLE_JAVA  # Immutable original


def test_agentic_self_healing_on_compilation_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    src = tmp_path / "src" / "demo" / "SqlDemo.java"
    src.parent.mkdir(parents=True)
    src.write_text(SAMPLE_JAVA, encoding="utf-8")

    finding = {
        "violation_id": "ISO-A.8-SQL-INJECTION",
        "method_key": "ws@rev:src/demo/SqlDemo.java#method:queryUser",
        "target_method": "demo.SqlDemo.queryUser(Connection, String)",
        "file_path": src.as_posix(),
        "reason": "SQL injection detected",
    }

    turn = 0

    def mock_llm_client(messages, **kwargs):
        nonlocal turn
        turn += 1
        if turn == 1:
            # Introduce syntax error
            return {
                "choices": [
                    {
                        "message": {
                            "tool_calls": [
                                {
                                    "id": "c1",
                                    "function": {
                                        "name": "edit_file",
                                        "arguments": json.dumps({
                                            "relative_path": "src/demo/SqlDemo.java",
                                            "old_str": "String sql = \"SELECT * FROM users WHERE id = '\" + userId + \"'\";",
                                            "new_str": "INVALID SYNTAX HERE;;;",
                                        }),
                                    },
                                }
                            ]
                        }
                    }
                ]
            }
        elif turn == 2:
            # Verify and see compilation failure
            return {
                "choices": [
                    {
                        "message": {
                            "tool_calls": [
                                {
                                    "id": "c2",
                                    "function": {
                                        "name": "run_verification",
                                        "arguments": "{}",
                                    },
                                }
                            ]
                        }
                    }
                ]
            }
        elif turn == 3:
            # Self-heal: fix syntax and finish
            return {
                "choices": [
                    {
                        "message": {
                            "tool_calls": [
                                {
                                    "id": "c3",
                                    "function": {
                                        "name": "edit_file",
                                        "arguments": json.dumps({
                                            "relative_path": "src/demo/SqlDemo.java",
                                            "old_str": "INVALID SYNTAX HERE;;;",
                                            "new_str": "String sql = \"SELECT * FROM users WHERE id = ?\";",
                                        }),
                                    },
                                },
                                {
                                    "id": "c4",
                                    "function": {
                                        "name": "finish_remediation",
                                        "arguments": json.dumps({
                                            "reason": "Self-healed syntax error and applied parameterized SQL query.",
                                        }),
                                    },
                                },
                            ]
                        }
                    }
                ]
            }
        return {"choices": [{"message": {"content": "done"}}]}

    def verify_current_source(env: IsolatedWorktreeEnvironment, _rule_id: str) -> AgentVerificationStatus:
        return _verification(compile_passed="INVALID SYNTAX" not in env.read_file("src/demo/SqlDemo.java"))

    monkeypatch.setattr(IsolatedWorktreeEnvironment, "run_full_verification", verify_current_source)
    service = AgenticRemediationService(llm_client=mock_llm_client)
    result = service.remediate_finding(finding, workspace_root=tmp_path, max_turns=6)
    assert result.status == "SUCCESS"
    assert "Self-healed syntax error" in result.reason


def test_missing_build_and_test_infrastructure_fail_closed(tmp_path: Path) -> None:
    src = tmp_path / "App.java"
    src.write_text("class App {}\n", encoding="utf-8")

    with IsolatedWorktreeEnvironment(tmp_path) as env:
        with patch(
            "codegraph.java.service.parse_java_source",
            return_value=SimpleNamespace(coverage="complete", diagnostics=[]),
        ):
            compile_ok, compile_output = env.compile_workspace()
        tests_ok, tests_output = env.run_tests()

    assert compile_ok is False
    assert "no supported Maven build" in compile_output
    assert tests_ok is False
    assert "no supported Maven build" in tests_output


def test_no_test_suite_is_a_vacuous_pass_not_a_failure(tmp_path: Path) -> None:
    src_dir = tmp_path / "src" / "main" / "java"
    src_dir.mkdir(parents=True)
    (src_dir / "App.java").write_text("class App {}\n", encoding="utf-8")
    (tmp_path / "pom.xml").write_text("<project/>", encoding="utf-8")

    with IsolatedWorktreeEnvironment(tmp_path) as env:
        tests_ok, tests_output = env.run_tests()

    assert tests_ok is True
    assert "no Java test suite was found" in tests_output


def test_compile_and_test_commands_skip_spotless(tmp_path: Path) -> None:
    src_dir = tmp_path / "src" / "main" / "java"
    src_dir.mkdir(parents=True)
    (src_dir / "App.java").write_text("class App {}\n", encoding="utf-8")
    (tmp_path / "pom.xml").write_text("<project/>", encoding="utf-8")
    test_dir = tmp_path / "src" / "test" / "java"
    test_dir.mkdir(parents=True)
    (test_dir / "AppTest.java").write_text("class AppTest {}\n", encoding="utf-8")

    with IsolatedWorktreeEnvironment(tmp_path) as env:
        with patch(
            "codegraph.java.service.parse_java_source",
            return_value=SimpleNamespace(coverage="complete", diagnostics=[]),
        ):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = SimpleNamespace(returncode=0, stdout="", stderr="")
                env.compile_workspace()
                env.run_tests()

    compile_args = mock_run.call_args_list[0].args[0]
    test_args = mock_run.call_args_list[1].args[0]
    assert "-Dspotless.apply.skip=true" in compile_args
    assert "-Dspotless.check.skip=true" in compile_args
    assert "-Dspotless.apply.skip=true" in test_args
    assert "-Dspotless.check.skip=true" in test_args


def test_build_and_policy_exceptions_fail_closed(tmp_path: Path) -> None:
    src = tmp_path / "App.java"
    src.write_text("class App { void run() {} }\n", encoding="utf-8")
    (tmp_path / "pom.xml").write_text("<project/>", encoding="utf-8")
    test_dir = tmp_path / "src" / "test" / "java"
    test_dir.mkdir(parents=True)
    (test_dir / "AppTest.java").write_text("class AppTest {}\n", encoding="utf-8")

    with IsolatedWorktreeEnvironment(tmp_path, target_method_key="invalid") as env:
        with patch("subprocess.run", side_effect=OSError("maven unavailable")):
            tests_ok, tests_output = env.run_tests()
        policy_ok, findings, remaining = env.evaluate_policy("TEST-RULE")

    assert tests_ok is False
    assert "maven unavailable" in tests_output
    assert policy_ok is False
    assert findings == [{"error": "policy_target_unavailable"}]
    assert remaining == ["TEST-RULE"]


def test_policy_gate_compares_scratch_candidate_to_immutable_baseline(
    tmp_path: Path,
) -> None:
    src = tmp_path / "src" / "demo" / "HashDemo.java"
    src.parent.mkdir(parents=True)
    original = (
        "package demo; class HashDemo { "
        "void use(String algorithm) {} "
        "void hash() { use(\"MD5\"); } }\n"
    )
    src.write_text(original, encoding="utf-8")
    snapshot = create_source_snapshot_from_bytes(
        workspace_root=tmp_path,
        source_path=src,
        source_bytes=original.encode(),
        method_selector="demo.HashDemo#hash()",
        expected_source_sha256=sha256_hex(original),
    )
    method_key = f"workspace@revision:src/demo/HashDemo.java#{snapshot.identity.source_key}"
    captured: dict[str, str] = {}

    def fake_verify_candidate(**kwargs):
        root = Path(kwargs["workspace_root"])
        captured["baseline"] = (root / kwargs["source"]).read_text(encoding="utf-8")
        captured["candidate"] = (root / kwargs["candidate"]).read_text(encoding="utf-8")
        return {
            "status": "POLICY_PASS",
            "policy_status": "PASS",
            "findings": {"candidate": []},
        }

    with IsolatedWorktreeEnvironment(tmp_path, target_method_key=method_key) as env:
        assert env.apply_replacement("src/demo/HashDemo.java", 'use("MD5")', 'use("SHA-256")')
        with patch(
            "codegraph.remediation.agentic.environment.verify_candidate",
            side_effect=fake_verify_candidate,
        ):
            passed, findings, remaining = env.evaluate_policy("ISO-A.10-WEAK-HASH")

    assert passed is True
    assert findings == []
    assert remaining == []
    assert 'use("MD5")' in captured["baseline"]
    assert 'use("SHA-256")' in captured["candidate"]
    assert src.read_text(encoding="utf-8") == original


def test_agentic_safe_refusal(tmp_path: Path) -> None:
    src = tmp_path / "src" / "demo" / "SqlDemo.java"
    src.parent.mkdir(parents=True)
    src.write_text(SAMPLE_JAVA, encoding="utf-8")

    finding = {
        "violation_id": "ISO-A.8-PATH-TRAVERSAL",
        "method_key": "ws@rev:src/demo/SqlDemo.java#method:queryUser",
        "target_method": "demo.SqlDemo.queryUser(Connection, String)",
        "file_path": src.as_posix(),
        "reason": "Path traversal detected",
    }

    def mock_llm_client(messages, **kwargs):
        return {
            "choices": [
                {
                    "message": {
                        "tool_calls": [
                            {
                                "id": "refuse_call",
                                "function": {
                                    "name": "refuse_remediation",
                                    "arguments": json.dumps({
                                        "reason": "Cannot safely determine directory jail policy without architectural configuration.",
                                    }),
                                },
                            }
                        ]
                    }
                }
            ]
        }

    service = AgenticRemediationService(llm_client=mock_llm_client)
    result = service.remediate_finding(finding, workspace_root=tmp_path, max_turns=3)
    assert result.status == "REFUSED"
    assert "jail policy" in result.reason
    assert result.modified_files == []


def test_agentic_dynamic_discovery_tools(tmp_path: Path) -> None:
    src = tmp_path / "src" / "demo" / "SqlDemo.java"
    src.parent.mkdir(parents=True)
    src.write_text(SAMPLE_JAVA, encoding="utf-8")

    finding = {
        "violation_id": "ISO-A.8-SQL-INJECTION",
        "method_key": "ws@rev:src/demo/SqlDemo.java#method:queryUser",
        "target_method": "demo.SqlDemo.queryUser(Connection, String)",
        "file_path": src.as_posix(),
        "reason": "SQL injection detected",
    }

    turn = 0

    def mock_llm_client(messages, **kwargs):
        nonlocal turn
        turn += 1
        if turn == 1:
            # Test find_files, search_code, search_graph_context
            return {
                "choices": [
                    {
                        "message": {
                            "tool_calls": [
                                {
                                    "id": "f1",
                                    "function": {
                                        "name": "find_files",
                                        "arguments": json.dumps({"pattern": "**/*.java"}),
                                    },
                                },
                                {
                                    "id": "s1",
                                    "function": {
                                        "name": "search_code",
                                        "arguments": json.dumps({"pattern": "SELECT"}),
                                    },
                                },
                                {
                                    "id": "g1",
                                    "function": {
                                        "name": "search_graph_context",
                                        "arguments": json.dumps({"symbol_name": "queryUser"}),
                                    },
                                },
                            ]
                        }
                    }
                ]
            }
        else:
            return {
                "choices": [
                    {
                        "message": {
                            "tool_calls": [
                                {
                                    "id": "finish",
                                    "function": {
                                        "name": "finish_remediation",
                                        "arguments": json.dumps({"reason": "Discovery tools evaluated."}),
                                    },
                                }
                            ]
                        }
                    }
                ]
            }

    service = AgenticRemediationService(llm_client=mock_llm_client)
    result = service.remediate_finding(finding, workspace_root=tmp_path, max_turns=3)
    assert len(result.turns) >= 2
    tool_results = result.turns[1].tool_results
    assert any(tr.name == "find_files" and "src/demo/SqlDemo.java" in tr.output for tr in tool_results)
    assert any(tr.name == "search_code" and "SELECT" in tr.output for tr in tool_results)
    assert any(tr.name == "search_graph_context" for tr in tool_results)
