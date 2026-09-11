"""Unit and integration tests for autonomous agentic remediation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codegraph.remediation.agentic import (
    AgenticRemediationService,
    IsolatedWorktreeEnvironment,
)

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

    service = AgenticRemediationService(llm_client=mock_llm_client)
    result = service.remediate_finding(finding, workspace_root=tmp_path, max_turns=5)

    assert result.status == "SUCCESS"
    assert "PreparedStatement" in result.diff
    assert "stmt.setString(1, userId)" in result.diff
    assert result.modified_files == ["src/demo/SqlDemo.java"]
    assert "Parameterized SQL query" in result.reason
    assert src.read_text(encoding="utf-8") == SAMPLE_JAVA  # Immutable original


def test_agentic_self_healing_on_compilation_failure(tmp_path: Path) -> None:
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

    service = AgenticRemediationService(llm_client=mock_llm_client)
    result = service.remediate_finding(finding, workspace_root=tmp_path, max_turns=6)
    assert result.status == "SUCCESS"
    assert "Self-healed syntax error" in result.reason


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
