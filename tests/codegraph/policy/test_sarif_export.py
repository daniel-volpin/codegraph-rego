"""Unit tests for SARIF 2.1.0 exporter and API router endpoint."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from codegraph.policy.sarif import SARIF_SCHEMA_URI, TOOL_NAME, export_findings_to_sarif


class TestSarifExport(unittest.TestCase):
    def test_export_empty_findings_to_sarif(self) -> None:
        sarif = export_findings_to_sarif([])

        self.assertEqual(sarif["$schema"], SARIF_SCHEMA_URI)
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(len(sarif["runs"]), 1)
        self.assertEqual(sarif["runs"][0]["tool"]["driver"]["name"], TOOL_NAME)
        self.assertEqual(sarif["runs"][0]["results"], [])

    def test_export_findings_to_sarif_maps_severity_and_locations(self) -> None:
        violations = [
            {
                "violation_id": "ISO-A.8-SQL-INJECTION",
                "severity": "high",
                "reason": "SQL injection detected in string query.",
                "file_path": "/app/src/main/java/com/acme/Repo.java",
                "snippet_start_line": 15,
                "snippet_end_line": 18,
                "code_snippet": "stmt.executeQuery(sql);",
                "method_key": "ws@rev:Repo.java#query",
                "target_method": "com.acme.Repo.query(String)",
                "decision_id": "dec-12345",
                "control_metadata": {
                    "title": "SQL Injection Control",
                    "description": "Ensure queries use parameterized statements.",
                },
            },
            {
                "violation_id": "ISO-A.10-WEAK-RANDOM",
                "severity": "medium",
                "reason": "Predictable randomness used.",
                "file_path": "/app/src/main/java/com/acme/Token.java",
                "start_line": 40,
                "end_line": 42,
                "evidence": {"source_code": "new Random().nextInt();"},
                "method_key": "ws@rev:Token.java#token",
            },
        ]

        sarif = export_findings_to_sarif(violations, workspace_root="/app")
        run = sarif["runs"][0]

        # Verify Rules
        rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
        self.assertIn("ISO-A.8-SQL-INJECTION", rules)
        self.assertIn("ISO-A.10-WEAK-RANDOM", rules)
        self.assertEqual(rules["ISO-A.8-SQL-INJECTION"]["defaultConfiguration"]["level"], "error")
        self.assertEqual(rules["ISO-A.10-WEAK-RANDOM"]["defaultConfiguration"]["level"], "warning")

        # Verify Results
        results = run["results"]
        self.assertEqual(len(results), 2)

        res1 = results[0]
        self.assertEqual(res1["ruleId"], "ISO-A.8-SQL-INJECTION")
        self.assertEqual(res1["level"], "error")
        self.assertEqual(res1["message"]["text"], "SQL injection detected in string query.")
        self.assertEqual(res1["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "src/main/java/com/acme/Repo.java")
        self.assertEqual(res1["locations"][0]["physicalLocation"]["region"]["startLine"], 15)
        self.assertEqual(res1["locations"][0]["physicalLocation"]["region"]["endLine"], 18)
        self.assertEqual(res1["locations"][0]["physicalLocation"]["region"]["snippet"]["text"], "stmt.executeQuery(sql);")
        self.assertEqual(res1["properties"]["methodKey"], "ws@rev:Repo.java#query")

        res2 = results[1]
        self.assertEqual(res2["ruleId"], "ISO-A.10-WEAK-RANDOM")
        self.assertEqual(res2["level"], "warning")
        self.assertEqual(res2["locations"][0]["physicalLocation"]["region"]["startLine"], 40)


class TestSarifExportApiEndpoint(unittest.TestCase):
    @patch("api.routers.policy.export_sarif")
    def test_sarif_export_endpoint_returns_json_response(self, mock_export):
        from api.routers.policy import router as policy_router

        mock_export.return_value = {
            "$schema": SARIF_SCHEMA_URI,
            "version": "2.1.0",
            "runs": [],
        }

        app = FastAPI()
        app.include_router(policy_router)
        client = TestClient(app)

        response = client.get("/policy/export/sarif")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "application/sarif+json; charset=utf-8")
        payload = response.json()
        self.assertEqual(payload["version"], "2.1.0")


if __name__ == "__main__":
    unittest.main()
