"""Permanent End-to-End Test Suite for CodeGraph Live Ingestion & Agentic Remediation.

This test requires a live Neo4j service (bolt://localhost:7687) and OPA.
Tagged with @pytest.mark.e2e so it can be run on demand via `make test-e2e`
without failing standard unit CI when Neo4j is offline.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from codegraph.db import shared_neo4j_driver
from codegraph.ingestion.service import ingest
from codegraph.policy.integration import evaluate_policies
from codegraph.remediation.agentic import AgenticRemediationService


def neo4j_available() -> bool:
    try:
        driver = shared_neo4j_driver()
        with driver.session() as s:
            s.run("RETURN 1")
        return True
    except Exception:
        return False


POM_XML = """<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.acme</groupId>
    <artifactId>user-service</artifactId>
    <version>1.0.0</version>
    <properties>
        <maven.compiler.source>21</maven.compiler.source>
        <maven.compiler.target>21</maven.compiler.target>
    </properties>
</project>
"""

SQL_SERVICE_JAVA = """package com.acme.service;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

public class UserService {

    public String getUserName(Connection conn, HttpServletRequest request) throws Exception {
        String userId = request.getParameter("userId");
        Statement stmt = conn.createStatement();
        String query = "SELECT name FROM users WHERE id = '" + userId + "'";
        ResultSet rs = stmt.executeQuery(query);
        if (rs.next()) {
            return rs.getString("name");
        }
        return null;
    }
}
"""

SERVLET_MOCK_JAVA = """package javax.servlet.http;
public interface HttpServletRequest {
    String getParameter(String name);
}
"""


@pytest.mark.e2e
def test_full_live_agentic_pipeline_e2e(tmp_path: Path) -> None:
    if not neo4j_available():
        pytest.skip("Live Neo4j service (bolt://localhost:7687) is offline.")

    driver = shared_neo4j_driver()
    with driver.session() as s:
        s.run("MATCH (n) DETACH DELETE n")

    (tmp_path / "pom.xml").write_text(POM_XML, encoding="utf-8")
    java_root = (tmp_path / "src/main/java").resolve()
    
    servlet_file = java_root / "javax/servlet/http/HttpServletRequest.java"
    servlet_file.parent.mkdir(parents=True, exist_ok=True)
    servlet_file.write_text(SERVLET_MOCK_JAVA, encoding="utf-8")

    service_file = java_root / "com/acme/service/UserService.java"
    service_file.parent.mkdir(parents=True, exist_ok=True)
    service_file.write_text(SQL_SERVICE_JAVA, encoding="utf-8")

    initial_hash = hashlib.sha256(service_file.read_bytes()).hexdigest()

    # Step 1: Live Ingestion with JDT
    pub = ingest(java_root.as_posix())
    assert pub.workspace_id and pub.revision_id

    # Step 2: Policy Evaluation
    policy_res = evaluate_policies(workspace_root=java_root.as_posix())
    violations = policy_res.get("violations", [])
    sqli_finding = next((v for v in violations if v.get("violation_id") == "ISO-A.8-SQL-INJECTION"), None)
    assert sqli_finding is not None, "Expected ISO-A.8-SQL-INJECTION violation"

    # Step 3: Run Agentic Remediation
    turn_count = 0

    def mock_agent_llm(messages, tools=None, **kwargs):
        nonlocal turn_count
        turn_count += 1

        if turn_count == 1:
            return {
                "choices": [
                    {
                        "message": {
                            "content": "Reading file to inspect SQL concatenation.",
                            "tool_calls": [
                                {
                                    "id": "t1",
                                    "function": {
                                        "name": "read_file",
                                        "arguments": json.dumps({
                                            "relative_path": "src/main/java/com/acme/service/UserService.java"
                                        }),
                                    },
                                }
                            ],
                        }
                    }
                ]
            }

        elif turn_count == 2:
            return {
                "choices": [
                    {
                        "message": {
                            "content": "Adding import and refactoring to PreparedStatement with parameter binding.",
                            "tool_calls": [
                                {
                                    "id": "t2_1",
                                    "function": {
                                        "name": "add_import",
                                        "arguments": json.dumps({
                                            "relative_path": "src/main/java/com/acme/service/UserService.java",
                                            "import_statement": "import java.sql.PreparedStatement;",
                                        }),
                                    },
                                },
                                {
                                    "id": "t2_2",
                                    "function": {
                                        "name": "edit_file",
                                        "arguments": json.dumps({
                                            "relative_path": "src/main/java/com/acme/service/UserService.java",
                                            "old_str": (
                                                "        Statement stmt = conn.createStatement();\n"
                                                "        String query = \"SELECT name FROM users WHERE id = '\" + userId + \"'\";\n"
                                                "        ResultSet rs = stmt.executeQuery(query);"
                                            ),
                                            "new_str": (
                                                "        String query = \"SELECT name FROM users WHERE id = ?\";\n"
                                                "        PreparedStatement stmt = conn.prepareStatement(query);\n"
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

        elif turn_count == 3:
            return {
                "choices": [
                    {
                        "message": {
                            "content": "Running 3-gate verification.",
                            "tool_calls": [
                                {
                                    "id": "t3",
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
            return {
                "choices": [
                    {
                        "message": {
                            "content": "Verification passed.",
                            "tool_calls": [
                                {
                                    "id": "t4",
                                    "function": {
                                        "name": "finish_remediation",
                                        "arguments": json.dumps({
                                            "reason": "Parameterized SQL query using PreparedStatement.",
                                        }),
                                    },
                                }
                            ],
                        }
                    }
                ]
            }

    service = AgenticRemediationService(llm_client=mock_agent_llm)
    result = service.remediate_finding(sqli_finding, workspace_root=tmp_path, max_turns=6)

    assert result.status == "SUCCESS"
    assert result.verification is not None
    assert result.verification.compile_passed is True
    assert result.verification.policy_passed is True
    assert result.verification.all_passed is True
    assert "import java.sql.PreparedStatement;" in result.diff
    assert "conn.prepareStatement(query)" in result.diff
    assert "stmt.setString(1, userId)" in result.diff

    # Verify original source remained 100% untouched
    assert hashlib.sha256(service_file.read_bytes()).hexdigest() == initial_hash
