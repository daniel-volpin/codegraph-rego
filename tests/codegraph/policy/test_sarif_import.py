"""Unit tests for universal SARIF v2.1.0 ingestion and Neo4j AST grounding."""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock

from fastapi import FastAPI
from fastapi.testclient import TestClient

from codegraph.policy.sarif_import import import_findings_from_sarif


class TestSarifImport(unittest.TestCase):
    def test_import_standard_sarif_payload(self) -> None:
        sarif_doc = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Semgrep",
                            "rules": [
                                {
                                    "id": "java.lang.security.audit.sqli.jdbc-sqli",
                                    "shortDescription": {"text": "JDBC SQL Injection"},
                                    "fullDescription": {"text": "Detected SQL string concatenation inside executeQuery."},
                                }
                            ],
                        }
                    },
                    "results": [
                        {
                            "ruleId": "java.lang.security.audit.sqli.jdbc-sqli",
                            "level": "error",
                            "message": {"text": "Potential SQL injection vulnerability."},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/main/java/com/acme/UserDao.java"},
                                        "region": {
                                            "startLine": 25,
                                            "endLine": 28,
                                            "snippet": {"text": "stmt.executeQuery(sql);"},
                                        },
                                    }
                                }
                            ],
                            "properties": {
                                "methodKey": "ws@rev:src/main/java/com/acme/UserDao.java#UserDao#query(String)",
                                "targetMethod": "com.acme.UserDao.query(String)",
                            },
                        }
                    ],
                }
            ],
        }

        findings = import_findings_from_sarif(sarif_doc)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["violation_id"], "java.lang.security.audit.sqli.jdbc-sqli")
        self.assertEqual(f["severity"], "high")
        self.assertEqual(f["snippet_start_line"], 25)
        self.assertEqual(f["snippet_end_line"], 28)
        self.assertEqual(f["code_snippet"], "stmt.executeQuery(sql);")
        self.assertEqual(f["method_key"], "ws@rev:src/main/java/com/acme/UserDao.java#UserDao#query(String)")
        self.assertEqual(f["target_method"], "com.acme.UserDao.query(String)")
        self.assertTrue(f["evidence"]["imported_from_sarif"])

    def test_import_with_neo4j_ast_resolution(self) -> None:
        mock_driver = MagicMock()
        mock_session = MagicMock()
        mock_driver.session.return_value.__enter__.return_value = mock_session
        mock_record = {
            "method_key": "ws1@rev1:src/main/java/com/acme/Repo.java#Repo#find(String)",
            "signature": "com.acme.Repo.find(String)",
            "file_path": "/app/src/main/java/com/acme/Repo.java",
        }
        mock_session.run.return_value.single.return_value = mock_record

        sarif_doc = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "CodeQL", "rules": []}},
                    "results": [
                        {
                            "ruleId": "java/sql-injection",
                            "level": "warning",
                            "message": {"text": "Query built from untrusted input."},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/main/java/com/acme/Repo.java"},
                                        "region": {"startLine": 45, "endLine": 48},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }

        findings = import_findings_from_sarif(sarif_doc, neo4j_driver=mock_driver)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["method_key"], "ws1@rev1:src/main/java/com/acme/Repo.java#Repo#find(String)")
        self.assertEqual(f["target_method"], "com.acme.Repo.find(String)")
        self.assertEqual(f["severity"], "medium")

    def test_rejects_invalid_sarif_version(self) -> None:
        with self.assertRaises(ValueError):
            import_findings_from_sarif({"version": "1.0.0"})


class TestSarifImportApi(unittest.TestCase):
    def test_import_sarif_endpoint(self) -> None:
        from api.routers.policy import router as policy_router

        app = FastAPI()
        app.include_router(policy_router)
        client = TestClient(app)

        sarif_doc = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "TestTool"}},
                    "results": [
                        {
                            "ruleId": "TEST-01",
                            "level": "note",
                            "message": {"text": "Test finding"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "Test.java"},
                                        "region": {"startLine": 1, "endLine": 5},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }

        response = client.post("/policy/import/sarif", json=sarif_doc)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "OK")
        self.assertEqual(data["count"], 1)
        self.assertEqual(data["violations"][0]["violation_id"], "TEST-01")
        self.assertEqual(data["violations"][0]["severity"], "low")


if __name__ == "__main__":
    unittest.main()
