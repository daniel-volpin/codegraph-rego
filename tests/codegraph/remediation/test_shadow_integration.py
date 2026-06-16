from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from codegraph.remediation.service import RemediationService
from codegraph.remediation.shadow import maybe_attach_shadow_result


class ShadowIntegrationTests(unittest.TestCase):
    def test_feature_flag_off_returns_exact_authoritative_payload(self) -> None:
        service = RemediationService(llm_client=lambda _messages, **_kwargs: "")
        authoritative = {"status": "INVALID", "violation_id": "v1", "error": "unsupported"}

        with patch("codegraph.remediation.shadow.settings", SimpleNamespace(remediation_shadow_lifecycle_enabled=False, remediation_shadow_sql_plugin_enabled=False)):
            result = maybe_attach_shadow_result(service, context={"rule_id": "ISO-A.8-SQL-INJECTION"}, authoritative_result=authoritative)

        self.assertEqual(result, authoritative)

    def test_shadow_fields_attach_without_changing_authoritative_status(self) -> None:
        service = RemediationService(llm_client=lambda _messages, **_kwargs: "")
        authoritative = {"status": "INVALID", "violation_id": "v1", "error": "unsupported"}

        with tempfile.TemporaryDirectory() as tmp:
            java_file = Path(tmp) / "Foo.java"
            java_file.write_text(
                """
class Foo {
  public java.sql.ResultSet find(java.sql.Connection conn, String name) throws Exception {
    String sql = \"SELECT * FROM users WHERE name = '\" + name + \"'\";
    java.sql.Statement stmt = conn.createStatement();
    return stmt.executeQuery(sql);
  }
}
""".strip(),
                encoding="utf-8",
            )
            context = {
                "rule_id": "ISO-A.8-SQL-INJECTION",
                "violation": {"violation_id": "v1"},
                "file_path": java_file.as_posix(),
                "target_method": "Foo.find(Connection,String)",
                "exact_method_source": """
public java.sql.ResultSet find(java.sql.Connection conn, String name) throws Exception {
    String sql = \"SELECT * FROM users WHERE name = '\" + name + \"'\";
    java.sql.Statement stmt = conn.createStatement();
    return stmt.executeQuery(sql);
}
""".strip(),
                "baseline_violations": [{"violation_id": "ISO-A.8-SQL-INJECTION"}],
            }

            with (
                patch("codegraph.remediation.shadow.settings", SimpleNamespace(remediation_shadow_lifecycle_enabled=True, remediation_shadow_sql_plugin_enabled=True)),
                patch("codegraph.remediation.shadow.PolicyEvaluator") as evaluator_cls,
            ):
                evaluator_cls.return_value.evaluate.return_value = {"violations": []}
                result = maybe_attach_shadow_result(service, context=context, authoritative_result=authoritative)

        self.assertEqual(result["status"], "INVALID")
        self.assertIn("shadow_lifecycle", result)
        self.assertIn("shadow_comparison", result)
        self.assertEqual(result["shadow_lifecycle"]["effective_runtime_mode"], "shadow_only")

    def test_shadow_failure_fails_closed(self) -> None:
        service = RemediationService(llm_client=lambda _messages, **_kwargs: "")
        authoritative = {"status": "INVALID", "violation_id": "v1", "error": "unsupported"}

        with (
            patch("codegraph.remediation.shadow.settings", SimpleNamespace(remediation_shadow_lifecycle_enabled=True, remediation_shadow_sql_plugin_enabled=True)),
            patch("codegraph.remediation.shadow._shadow_registry", side_effect=RuntimeError("boom")),
        ):
            result = maybe_attach_shadow_result(service, context={"rule_id": "ISO-A.8-SQL-INJECTION", "violation": {"violation_id": "v1"}}, authoritative_result=authoritative)

        self.assertEqual(result["status"], "INVALID")
        self.assertEqual(result["shadow_lifecycle"]["shadow_error"]["code"], "shadow_exception")


if __name__ == "__main__":
    unittest.main()