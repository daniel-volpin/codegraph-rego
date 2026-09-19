"""Tests for agentic workspace inspection tools and execution."""

from __future__ import annotations

import json
from pathlib import Path

from codegraph.remediation.agentic.contracts import AgentToolCall
from codegraph.remediation.agentic.environment import IsolatedWorktreeEnvironment
from codegraph.remediation.agentic.tools import AgentToolExecutor
from codegraph.remediation.agentic.workspace_search import inspect_workspace_class_api

HELPER_JAVA = """package org.example.helpers;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Statement;

public class DatabaseHelper {
    public static boolean hideSQLErrors = true;

    public DatabaseHelper() {}

    public static Connection getSqlConnection() throws Exception {
        return null;
    }

    public static PreparedStatement getSqlPreparedStatement(String sql, int[] columnIndexes) throws Exception {
        return null;
    }

    public static Statement getSqlStatement() throws Exception {
        return null;
    }
}
"""


def test_inspect_workspace_class_api_extracts_methods_and_fields(tmp_path: Path) -> None:
    src = tmp_path / "src" / "main" / "java" / "org" / "example" / "helpers" / "DatabaseHelper.java"
    src.parent.mkdir(parents=True)
    src.write_text(HELPER_JAVA, encoding="utf-8")

    api = inspect_workspace_class_api(tmp_path, "DatabaseHelper")
    assert api["class_name"] == "DatabaseHelper"
    assert "DatabaseHelper.java" in api["file_path"]
    assert any("getSqlConnection" in m for m in api["methods"])
    assert any("getSqlPreparedStatement" in m for m in api["methods"])
    assert any("hideSQLErrors" in f for f in api["fields"])


def test_agent_tool_executor_executes_inspect_class_api(tmp_path: Path) -> None:
    src = tmp_path / "src" / "main" / "java" / "org" / "example" / "helpers" / "DatabaseHelper.java"
    src.parent.mkdir(parents=True)
    src.write_text(HELPER_JAVA, encoding="utf-8")

    with IsolatedWorktreeEnvironment(tmp_path) as env:
        executor = AgentToolExecutor(env, target_rule_id="ISO-A.8-SQL-INJECTION")
        call = AgentToolCall(
            call_id="call_inspect_1",
            name="inspect_class_api",
            arguments={"class_name": "DatabaseHelper"},
        )
        res = executor.execute(call)
        assert res.success is True
        data = json.loads(res.output)
        assert data["class_name"] == "DatabaseHelper"
        assert len(data["methods"]) >= 3
