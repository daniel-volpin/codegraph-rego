from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from codegraph.remediation.plugin_types import (
    PipelineVerificationContract,
    PluginDescriptor,
    PluginProposal,
    RepairPatternContract,
)
from codegraph.remediation.repair_intent import RepairIntent, RepairIntentKind, SourceSpan, StructuredEditOp
from codegraph.remediation.result_models import ArtifactKind, Disposition, TransformationStrategy
from codegraph.remediation.service import RemediationService
from codegraph.remediation.shadow import maybe_attach_shadow_result
from codegraph.remediation.verification import BuildRequirement


class ShadowIntegrationTests(unittest.TestCase):
    def test_java_parse_validator_fails_for_invalid_generated_java(self) -> None:
        class InvalidJavaPlugin:
            descriptor = PluginDescriptor(
                plugin_id="invalid-java",
                plugin_version="1.0.0",
                supported_languages=["java"],
                supported_rule_ids=["ISO-A.8-SQL-INJECTION"],
                patterns=[
                    RepairPatternContract(
                        pattern_id="BROKEN",
                        pattern_version="1.0.0",
                        transformation_strategy=TransformationStrategy.TYPED_STRUCTURED_EDITS,
                        max_edit_scope_lines=1,
                        pipeline_verification=PipelineVerificationContract(require_parse=True, build_requirement=BuildRequirement.NEVER),
                        auto_apply_capable=False,
                    )
                ],
            )

            def propose(self, context: dict[str, object]) -> PluginProposal:
                return PluginProposal(
                    artifact_kind=ArtifactKind.PATCH,
                    disposition=Disposition.REVIEW_REQUIRED,
                    repair_intent=RepairIntent(
                        kind=RepairIntentKind.STRUCTURED_EDIT,
                        rule_id="ISO-A.8-SQL-INJECTION",
                        support_tier="manual",
                        target=SourceSpan(file_path=str(context["file_path"]), method_signature=str(context["target_method"])),
                        operations=[
                            StructuredEditOp(
                                start_line=2,
                                end_line=2,
                                original_lines=['    String sql = "SELECT * FROM users WHERE name = " + name;'],
                                replacement_lines=['    String sql = ;'],
                            )
                        ],
                    ),
                    patch_pattern=self.descriptor.patterns[0],
                    evidence_complete=True,
                    project_policy_dependency_resolved=True,
                    details={
                        "reproducibility_key": "invalid-java-case",
                        "patch_artifact": {
                            "target_file": str(context["file_path"]),
                            "anchor_method": str(context["target_method"]),
                            "edits": [
                                {
                                    "start_line": 2,
                                    "end_line": 2,
                                    "original_lines": ['    String sql = "SELECT * FROM users WHERE name = " + name;'],
                                    "replacement_lines": ['    String sql = ;'],
                                }
                            ],
                        },
                    },
                )

            def evaluate_semantics(self, *, context, proposal, updated_method_source):
                return []

        service = RemediationService(llm_client=lambda _messages, **_kwargs: "")
        authoritative = {"status": "INVALID", "violation_id": "v1", "error": "unsupported"}

        with tempfile.TemporaryDirectory() as tmp:
            java_file = Path(tmp) / "Foo.java"
            java_file.write_text(
                """
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

class Foo {
    public ResultSet find(Connection conn, String name) throws Exception {
    String sql = "SELECT * FROM users WHERE name = " + name;
        Statement stmt = conn.createStatement();
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
public ResultSet find(Connection conn, String name) throws Exception {
    String sql = "SELECT * FROM users WHERE name = " + name;
        Statement stmt = conn.createStatement();
    return stmt.executeQuery(sql);
}
""".strip(),
                "baseline_violations": [{"violation_id": "ISO-A.8-SQL-INJECTION"}],
            }

            with (
                patch("codegraph.remediation.shadow.settings", SimpleNamespace(remediation_shadow_lifecycle_enabled=True, remediation_shadow_sql_plugin_enabled=True)),
                patch("codegraph.remediation.shadow._shadow_registry", return_value=SimpleNamespace(resolve=lambda **_kwargs: InvalidJavaPlugin())),
                patch("codegraph.remediation.shadow.PolicyEvaluator") as evaluator_cls,
                patch.object(
                    service,
                    "_apply_method_edits",
                    return_value=(
                        [
                            "public ResultSet find(Connection conn, String name) throws Exception {",
                            "    String sql = ;",
                            "    Statement stmt = conn.createStatement();",
                            "    return stmt.executeQuery(sql);",
                            "}",
                        ],
                        "public ResultSet find(Connection conn, String name) throws Exception {\n    String sql = ;\n    Statement stmt = conn.createStatement();\n    return stmt.executeQuery(sql);\n}",
                    ),
                ),
                patch.object(
                    service,
                    "_replace_method_in_source",
                    return_value=(
                        "import java.sql.Connection;\nimport java.sql.ResultSet;\nimport java.sql.Statement;\nclass Foo {\npublic ResultSet find(Connection conn, String name) throws Exception {\n    String sql = ;\n    Statement stmt = conn.createStatement();\n    return stmt.executeQuery(sql);\n}\n}",
                        None,
                        None,
                    ),
                ),
            ):
                evaluator_cls.return_value.evaluate.return_value = {"violations": []}
                result = maybe_attach_shadow_result(service, context=context, authoritative_result=authoritative)

        java_parse_checks = [
            check
            for check in result["shadow_lifecycle"]["pipeline_checks"]
            if check["validator_id"] == "pipeline.java_parse"
        ]
        self.assertEqual(java_parse_checks[0]["state"], "FAIL")
        self.assertFalse(result["shadow_lifecycle"]["assurance_verified"])

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
        self.assertFalse(result["shadow_lifecycle"]["auto_apply_eligible"])
        self.assertNotEqual(result["shadow_lifecycle"]["recommended_disposition"], "auto_apply")

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