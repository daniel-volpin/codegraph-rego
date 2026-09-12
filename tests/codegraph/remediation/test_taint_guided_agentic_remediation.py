"""Unit tests for interprocedural taint-guided multi-file agentic remediation."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from codegraph.remediation.agentic.agent import (
    AgenticRemediationService,
    _build_initial_user_prompt,
    _format_taint_path_dossier,
)
from codegraph.remediation.agentic.contracts import AgentRemediationResult


class TestTaintGuidedAgenticRemediation(unittest.TestCase):
    def test_format_taint_path_dossier(self) -> None:
        taint_paths = [
            {
                "sink_type": "sql",
                "hops": 2,
                "chain": [
                    {"signature": "UserController.findUser(String)", "file_path": "UserController.java"},
                    {"signature": "UserService.getUser(String)", "file_path": "UserService.java"},
                    {"signature": "UserDao.query(String)", "file_path": "UserDao.java"},
                ],
            }
        ]
        dossier = _format_taint_path_dossier(taint_paths)
        self.assertIn("Interprocedural Taint Propagation Trace", dossier)
        self.assertIn("SQL sink, 2 hops", dossier)
        self.assertIn("UserController.findUser(String)", dossier)
        self.assertIn("UserService.getUser(String)", dossier)
        self.assertIn("UserDao.query(String)", dossier)

    def test_build_initial_user_prompt_includes_strategy_and_trace(self) -> None:
        finding = {
            "violation_id": "ISO-A.8-SQL-INJECTION",
            "target_method": "com.acme.UserDao.query(String)",
            "file_path": "src/main/java/com/acme/UserDao.java",
            "reason": "SQL query concatenation detected.",
            "code_snippet": "stmt.executeQuery(sql);",
            "taint_paths": [
                {
                    "sink_type": "sql",
                    "hops": 1,
                    "chain": [
                        {"signature": "Service.process(String)"},
                        {"signature": "Dao.query(String)"},
                    ],
                }
            ],
        }
        prompt = _build_initial_user_prompt(finding)
        self.assertIn("Target Security Violation: ISO-A.8-SQL-INJECTION", prompt)
        self.assertIn("PreparedStatement", prompt)
        self.assertIn("Interprocedural Taint Propagation Trace", prompt)

    def test_multi_file_agentic_repair_execution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir) / "project"
            root.mkdir()
            controller_file = root / "UserController.java"
            controller_file.write_text(
                "package com.acme;\npublic class UserController {\n  public void handle(String input) {}\n}\n",
                encoding="utf-8",
            )
            dao_file = root / "UserDao.java"
            dao_file.write_text(
                "package com.acme;\npublic class UserDao {\n  public void query(String sql) {\n    java.sql.Statement stmt = null;\n  }\n}\n",
                encoding="utf-8",
            )

            # Mock LLM executing multi-file edits and finishing
            turns_responses = [
                # Turn 1: Add import and edit UserDao.java
                {
                    "choices": [
                        {
                            "message": {
                                "content": "I will parameterize the query in UserDao.java.",
                                "tool_calls": [
                                    {
                                        "id": "tc1",
                                        "function": {
                                            "name": "edit_file",
                                            "arguments": {
                                                "relative_path": "UserDao.java",
                                                "old_str": "java.sql.Statement stmt = null;",
                                                "new_str": "java.sql.PreparedStatement stmt = null;",
                                            },
                                        },
                                    }
                                ],
                            }
                        }
                    ]
                },
                # Turn 2: Run verification
                {
                    "choices": [
                        {
                            "message": {
                                "content": "Let me verify the changes.",
                                "tool_calls": [
                                    {
                                        "id": "tc2",
                                        "function": {
                                            "name": "run_verification",
                                            "arguments": {},
                                        },
                                    }
                                ],
                            }
                        }
                    ]
                },
                # Turn 3: Finish remediation
                {
                    "choices": [
                        {
                            "message": {
                                "content": "Remediation verified successfully.",
                                "tool_calls": [
                                    {
                                        "id": "tc3",
                                        "function": {
                                            "name": "finish_remediation",
                                            "arguments": {"reason": "Converted Statement to PreparedStatement."},
                                        },
                                    }
                                ],
                            }
                        }
                    ]
                },
            ]

            turn_iter = iter(turns_responses)

            def mock_client(messages, tools, model):
                return next(turn_iter)

            service = AgenticRemediationService(llm_client=mock_client)
            result = service.remediate_finding(
                {
                    "violation_id": "ISO-A.8-SQL-INJECTION",
                    "target_method": "com.acme.UserDao.query(String)",
                    "file_path": "UserDao.java",
                    "code_snippet": "java.sql.Statement stmt = null;",
                },
                workspace_root=root,
                max_turns=5,
            )

            self.assertIsInstance(result, AgentRemediationResult)
            self.assertEqual(result.status, "SUCCESS")
            self.assertEqual(len(result.modified_files), 1)
            self.assertIn("UserDao.java", result.modified_files)


if __name__ == "__main__":
    unittest.main()
