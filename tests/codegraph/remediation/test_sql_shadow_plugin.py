from __future__ import annotations

import unittest
from typing import cast
from unittest.mock import patch

from codegraph.remediation.plugin_types import RepairPatternContract
from codegraph.remediation.result_models import ArtifactKind, LifecycleReasonCode
from codegraph.remediation.sql_shadow_plugin import JdbcSqlShadowPlugin


def _context(*, file_path: str, target_method: str, source: str) -> dict[str, object]:
    return {
        "rule_id": "ISO-A.8-SQL-INJECTION",
        "file_path": file_path,
        "target_method": target_method,
        "exact_method_source": source,
        "baseline_violations": [{"violation_id": "ISO-A.8-SQL-INJECTION"}],
    }


class JdbcSqlShadowPluginTests(unittest.TestCase):
    def setUp(self) -> None:
        self.plugin = JdbcSqlShadowPlugin()

    def test_sql_val_001_single_string_value_execute_query(self) -> None:
        proposal = self.plugin.propose(
            _context(
                file_path="src/main/java/com/example/Foo.java",
                target_method="com.example.Foo.findByName(String)",
                source="""
public ResultSet findByName(Connection conn, String name) throws Exception {
    String sql = \"SELECT * FROM users WHERE name = '\" + name + \"'\";
    Statement stmt = conn.createStatement();
    return stmt.executeQuery(sql);
}
""".strip(),
            )
        )

        self.assertEqual(proposal.artifact_kind, ArtifactKind.PATCH)
        self.assertIsNotNone(proposal.patch_pattern)
        patch_pattern = cast(RepairPatternContract, proposal.patch_pattern)
        self.assertEqual(patch_pattern.pattern_id, "SQL-VAL-001")
        patch = proposal.details["patch_artifact"]
        replacement = patch["edits"][2]["replacement_lines"]
        self.assertIn("stmt.setString(1, name);", replacement[0])
        self.assertIn("return stmt.executeQuery();", replacement[1])

    def test_sql_val_001_multiple_values_preserves_binding_order_and_types(self) -> None:
        proposal = self.plugin.propose(
            _context(
                file_path="src/main/java/com/example/Foo.java",
                target_method="com.example.Foo.find(String,int,boolean)",
                source="""
public ResultSet find(Connection conn, String name, int age, boolean active) throws Exception {
    String sql = \"SELECT * FROM users WHERE name = '\" + name + \"' AND age = \" + age + \" AND active = \" + active;
    Statement stmt = conn.createStatement();
    return stmt.executeQuery(sql);
}
""".strip(),
            )
        )

        self.assertEqual(proposal.artifact_kind, ArtifactKind.PATCH)
        bindings = proposal.details["bindings"]
        self.assertEqual([binding["expression"] for binding in bindings], ["name", "age", "active"])
        self.assertEqual([binding["binding_method"] for binding in bindings], ["setString", "setInt", "setBoolean"])

    def test_sql_val_002_inline_execute_update(self) -> None:
        proposal = self.plugin.propose(
            _context(
                file_path="src/main/java/com/example/Foo.java",
                target_method="com.example.Foo.update(boolean,long)",
                source="""
public int update(Connection conn, boolean active, long id) throws Exception {
    Statement stmt = conn.createStatement();
    return stmt.executeUpdate(\"UPDATE users SET active = \" + active + \" WHERE id = \" + id);
}
""".strip(),
            )
        )

        self.assertEqual(proposal.artifact_kind, ArtifactKind.PATCH)
        self.assertIsNotNone(proposal.patch_pattern)
        patch_pattern = cast(RepairPatternContract, proposal.patch_pattern)
        self.assertEqual(patch_pattern.pattern_id, "SQL-VAL-002")
        patch = proposal.details["patch_artifact"]
        self.assertIn("prepareStatement(\"UPDATE users SET active = ? WHERE id = ?\")", patch["edits"][0]["replacement_lines"][0])
        self.assertIn("stmt.setBoolean(1, active);", patch["edits"][1]["replacement_lines"][0])
        self.assertIn("return stmt.executeUpdate();", patch["edits"][1]["replacement_lines"][2])

    def test_sql_patterns_are_candidate_only(self) -> None:
        for pattern in self.plugin.descriptor.patterns:
            self.assertFalse(pattern.auto_apply_capable)

    def test_dynamic_table_name_emits_no_patch(self) -> None:
        proposal = self.plugin.propose(
            _context(
                file_path="src/main/java/com/example/Foo.java",
                target_method="com.example.Foo.find(String,String)",
                source="""
public ResultSet find(Connection conn, String table, String id) throws Exception {
    String sql = \"SELECT * FROM \" + table + \" WHERE id = \" + id;
    Statement stmt = conn.createStatement();
    return stmt.executeQuery(sql);
}
""".strip(),
            )
        )

        self.assertNotEqual(proposal.artifact_kind, ArtifactKind.PATCH)
        self.assertIn(LifecycleReasonCode.UNSUPPORTED_REPAIR_PATTERN, proposal.reason_codes)

    def test_dynamic_order_by_emits_no_patch(self) -> None:
        proposal = self.plugin.propose(
            _context(
                file_path="src/main/java/com/example/Foo.java",
                target_method="com.example.Foo.find(String)",
                source="""
public ResultSet find(Connection conn, String sortBy) throws Exception {
    String sql = \"SELECT * FROM users ORDER BY \" + sortBy;
    Statement stmt = conn.createStatement();
    return stmt.executeQuery(sql);
}
""".strip(),
            )
        )

        self.assertNotEqual(proposal.artifact_kind, ArtifactKind.PATCH)
        self.assertEqual(proposal.details["near_miss_classification"], "dynamic_order_by")

    def test_dynamic_operator_emits_no_patch(self) -> None:
        proposal = self.plugin.propose(
            _context(
                file_path="src/main/java/com/example/Foo.java",
                target_method="com.example.Foo.find(String,String)",
                source="""
public ResultSet find(Connection conn, String operator, String age) throws Exception {
    String sql = "SELECT * FROM users WHERE age " + operator + " " + age;
    Statement stmt = conn.createStatement();
    return stmt.executeQuery(sql);
}
""".strip(),
            )
        )

        self.assertNotEqual(proposal.artifact_kind, ArtifactKind.PATCH)
        self.assertEqual(proposal.details["near_miss_classification"], "dynamic_operator")

    def test_dynamic_clause_emits_no_patch(self) -> None:
        proposal = self.plugin.propose(
            _context(
                file_path="src/main/java/com/example/Foo.java",
                target_method="com.example.Foo.find(String,int)",
                source="""
public ResultSet find(Connection conn, String predicate, int id) throws Exception {
    String sql = "SELECT * FROM users WHERE " + predicate + " AND id = " + id;
    Statement stmt = conn.createStatement();
    return stmt.executeQuery(sql);
}
""".strip(),
            )
        )

        self.assertNotEqual(proposal.artifact_kind, ArtifactKind.PATCH)
        self.assertEqual(proposal.details["near_miss_classification"], "dynamic_clause")

    def test_cross_method_query_construction_emits_no_patch(self) -> None:
        proposal = self.plugin.propose(
            _context(
                file_path="src/main/java/com/example/Foo.java",
                target_method="com.example.Foo.find(String)",
                source="""
public ResultSet find(Connection conn, String user) throws Exception {
    String sql = buildQuery(user);
    Statement stmt = conn.createStatement();
    return stmt.executeQuery(sql);
}
""".strip(),
            )
        )

        self.assertNotEqual(proposal.artifact_kind, ArtifactKind.PATCH)
        self.assertIn(LifecycleReasonCode.INSUFFICIENT_EVIDENCE, proposal.reason_codes)

    def test_unresolved_binding_type_emits_no_patch(self) -> None:
        proposal = self.plugin.propose(
            _context(
                file_path="src/main/java/com/example/Foo.java",
                target_method="com.example.Foo.find(Object)",
                source="""
public ResultSet find(Connection conn, Object filter) throws Exception {
    String sql = \"SELECT * FROM users WHERE name = '\" + filter + \"'\";
    Statement stmt = conn.createStatement();
    return stmt.executeQuery(sql);
}
""".strip(),
            )
        )

        self.assertNotEqual(proposal.artifact_kind, ArtifactKind.PATCH)
        self.assertIn(LifecycleReasonCode.INSUFFICIENT_EVIDENCE, proposal.reason_codes)

    def test_unresolved_connection_expression_emits_no_patch(self) -> None:
        proposal = self.plugin.propose(
            _context(
                file_path="src/main/java/com/example/Foo.java",
                target_method="com.example.Foo.find(String)",
                source="""
public ResultSet find(String name) throws Exception {
    String sql = \"SELECT * FROM users WHERE name = '\" + name + \"'\";
    Statement stmt = getConnection().createStatement();
    return stmt.executeQuery(sql);
}
""".strip(),
            )
        )

        self.assertNotEqual(proposal.artifact_kind, ArtifactKind.PATCH)
        self.assertIn(LifecycleReasonCode.INSUFFICIENT_EVIDENCE, proposal.reason_codes)

    def test_escaped_literals_and_literal_question_mark_do_not_inflate_placeholder_count(self) -> None:
        proposal = self.plugin.propose(
            _context(
                file_path="src/main/java/com/example/Foo.java",
                target_method="com.example.Foo.find(String)",
                source="""
public ResultSet find(Connection conn, String name) throws Exception {
    String sql = "SELECT * FROM users WHERE note = 'C:\\\\temp\\\\?' AND label = 'O''Reilly?' AND name = '" + name + "'";
    Statement stmt = conn.createStatement();
    return stmt.executeQuery(sql);
}
""".strip(),
            )
        )

        self.assertEqual(proposal.artifact_kind, ArtifactKind.PATCH)
        self.assertEqual(proposal.details["placeholder_count"], 1)
        self.assertIn("C:\\temp\\?", proposal.details["parameterized_sql"])

    def test_multiline_declarations_are_supported(self) -> None:
        proposal = self.plugin.propose(
            _context(
                file_path="src/main/java/com/example/Foo.java",
                target_method="com.example.Foo.find(String)",
                source="""
public ResultSet find(Connection conn, String name) throws Exception {
    String sql =
        "SELECT * FROM users WHERE name = '" + name + "'";
    Statement stmt =
        conn.createStatement();
    return stmt.executeQuery(
        sql
    );
}
""".strip(),
            )
        )

        self.assertEqual(proposal.artifact_kind, ArtifactKind.PATCH)
        self.assertGreaterEqual(proposal.details["patch_artifact"]["edits"][0]["end_line"], proposal.details["patch_artifact"]["edits"][0]["start_line"])

    def test_execute_replacement_noop_still_changes_method_via_bindings(self) -> None:
        with patch("codegraph.remediation.sql_shadow_plugin._replace_execute_invocation_text", return_value="return stmt.executeQuery(sql);"):
            proposal = self.plugin.propose(
                _context(
                    file_path="src/main/java/com/example/Foo.java",
                    target_method="com.example.Foo.find(String)",
                    source="""
public ResultSet find(Connection conn, String name) throws Exception {
    String sql = "SELECT * FROM users WHERE name = '" + name + "'";
    Statement stmt = conn.createStatement();
    return stmt.executeQuery(sql);
}
""".strip(),
                )
            )

        self.assertEqual(proposal.artifact_kind, ArtifactKind.PATCH)
        replacement_lines = proposal.details["patch_artifact"]["edits"][2]["replacement_lines"]
        self.assertIn("stmt.setString(1, name);", replacement_lines[0])
        self.assertEqual(replacement_lines[1], "return stmt.executeQuery(sql);")

    def test_distinct_reproducibility_keys_for_distinct_abstentions(self) -> None:
        first = self.plugin.propose(
            _context(
                file_path="src/main/java/com/example/Foo.java",
                target_method="com.example.Foo.find(String)",
                source="""
public ResultSet find(Connection conn, String sortBy) throws Exception {
    String sql = "SELECT * FROM users ORDER BY " + sortBy;
    Statement stmt = conn.createStatement();
    return stmt.executeQuery(sql);
}
""".strip(),
            )
        )
        second = self.plugin.propose(
            _context(
                file_path="src/main/java/com/example/Foo.java",
                target_method="com.example.Foo.find(String)",
                source="""
public ResultSet find(Connection conn, String user) throws Exception {
    String sql = buildQuery(user);
    Statement stmt = conn.createStatement();
    return stmt.executeQuery(sql);
}
""".strip(),
            )
        )

        self.assertNotEqual(first.details["reproducibility_key"], second.details["reproducibility_key"])

    def test_semantic_validators_fail_for_undeclared_prepared_statement_variable(self) -> None:
        proposal = self.plugin.propose(
            _context(
                file_path="src/main/java/com/example/Foo.java",
                target_method="com.example.Foo.find(String)",
                source="""
public ResultSet find(Connection conn, String name) throws Exception {
    String sql = "SELECT * FROM users WHERE name = '" + name + "'";
    Statement stmt = conn.createStatement();
    return stmt.executeQuery(sql);
}
""".strip(),
            )
        )

        validators = self.plugin.evaluate_semantics(
            context={},
            proposal=proposal,
            updated_method_source="""
public ResultSet find(Connection conn, String name) throws Exception {
    String sql = "SELECT * FROM users WHERE name = ?";
    stmt.setString(1, name);
    return stmt.executeQuery();
}
""".strip(),
        )

        states = {validator.validator_id: validator.state for validator in validators}
        self.assertEqual(states["sql.prepared_statement_declared"].value, "FAIL")

    def test_semantic_validators_fail_for_wrong_executed_statement_variable(self) -> None:
        proposal = self.plugin.propose(
            _context(
                file_path="src/main/java/com/example/Foo.java",
                target_method="com.example.Foo.find(String)",
                source="""
public ResultSet find(Connection conn, String name) throws Exception {
    String sql = "SELECT * FROM users WHERE name = '" + name + "'";
    Statement stmt = conn.createStatement();
    return stmt.executeQuery(sql);
}
""".strip(),
            )
        )

        validators = self.plugin.evaluate_semantics(
            context={},
            proposal=proposal,
            updated_method_source="""
public ResultSet find(Connection conn, String name) throws Exception {
    String sql = "SELECT * FROM users WHERE name = ?";
    java.sql.PreparedStatement stmt = conn.prepareStatement(sql);
    java.sql.PreparedStatement other = conn.prepareStatement(sql);
    stmt.setString(1, name);
    return other.executeQuery();
}
""".strip(),
        )

        states = {validator.validator_id: validator.state for validator in validators}
        self.assertEqual(states["sql.executed_prepared_statement"].value, "FAIL")

    def test_semantic_validators_fail_for_duplicate_binding_indexes(self) -> None:
        proposal = self.plugin.propose(
            _context(
                file_path="src/main/java/com/example/Foo.java",
                target_method="com.example.Foo.find(String,int)",
                source="""
public ResultSet find(Connection conn, String name, int age) throws Exception {
    String sql = "SELECT * FROM users WHERE name = '" + name + "' AND age = " + age;
    Statement stmt = conn.createStatement();
    return stmt.executeQuery(sql);
}
""".strip(),
            )
        )

        validators = self.plugin.evaluate_semantics(
            context={},
            proposal=proposal,
            updated_method_source="""
public ResultSet find(Connection conn, String name, int age) throws Exception {
    String sql = "SELECT * FROM users WHERE name = ? AND age = ?";
    java.sql.PreparedStatement stmt = conn.prepareStatement(sql);
    stmt.setString(1, name);
    stmt.setInt(1, age);
    return stmt.executeQuery();
}
""".strip(),
        )

        states = {validator.validator_id: validator.state for validator in validators}
        self.assertEqual(states["sql.binding_order"].value, "FAIL")

    def test_semantic_validators_fail_for_missing_binding_index(self) -> None:
        proposal = self.plugin.propose(
            _context(
                file_path="src/main/java/com/example/Foo.java",
                target_method="com.example.Foo.find(String,int)",
                source="""
public ResultSet find(Connection conn, String name, int age) throws Exception {
    String sql = "SELECT * FROM users WHERE name = '" + name + "' AND age = " + age;
    Statement stmt = conn.createStatement();
    return stmt.executeQuery(sql);
}
""".strip(),
            )
        )

        validators = self.plugin.evaluate_semantics(
            context={},
            proposal=proposal,
            updated_method_source="""
public ResultSet find(Connection conn, String name, int age) throws Exception {
    String sql = "SELECT * FROM users WHERE name = ? AND age = ?";
    java.sql.PreparedStatement stmt = conn.prepareStatement(sql);
    stmt.setString(1, name);
    stmt.setInt(3, age);
    return stmt.executeQuery();
}
""".strip(),
        )

        states = {validator.validator_id: validator.state for validator in validators}
        self.assertEqual(states["sql.binding_order"].value, "FAIL")

    def test_semantic_validators_fail_for_placeholder_binding_mismatch(self) -> None:
        proposal = self.plugin.propose(
            _context(
                file_path="src/main/java/com/example/Foo.java",
                target_method="com.example.Foo.find(String,int)",
                source="""
public ResultSet find(Connection conn, String name, int age) throws Exception {
    String sql = "SELECT * FROM users WHERE name = '" + name + "' AND age = " + age;
    Statement stmt = conn.createStatement();
    return stmt.executeQuery(sql);
}
""".strip(),
            )
        )

        validators = self.plugin.evaluate_semantics(
            context={},
            proposal=proposal,
            updated_method_source="""
public ResultSet find(Connection conn, String name, int age) throws Exception {
    String sql = "SELECT * FROM users WHERE name = ? AND age = ?";
    java.sql.PreparedStatement stmt = conn.prepareStatement(sql);
    stmt.setString(1, name);
    return stmt.executeQuery();
}
""".strip(),
        )

        states = {validator.validator_id: validator.state for validator in validators}
        self.assertEqual(states["sql.placeholder_count"].value, "FAIL")

    def test_semantic_validators_pass_for_matching_declared_type_and_setter(self) -> None:
        proposal = self.plugin.propose(
            _context(
                file_path="src/main/java/com/example/Foo.java",
                target_method="com.example.Foo.find(String,int)",
                source="""
public ResultSet find(Connection conn, String name, int age) throws Exception {
    String sql = "SELECT * FROM users WHERE name = '" + name + "' AND age = " + age;
    Statement stmt = conn.createStatement();
    return stmt.executeQuery(sql);
}
""".strip(),
            )
        )

        validators = self.plugin.evaluate_semantics(
            context={"exact_method_source": proposal.details["patch_artifact"]["anchor_method"]},
            proposal=proposal,
            updated_method_source="""
public ResultSet find(Connection conn, String name, int age) throws Exception {
    String sql = "SELECT * FROM users WHERE name = ? AND age = ?";
    java.sql.PreparedStatement stmt = conn.prepareStatement(sql);
    stmt.setString(1, name);
    stmt.setInt(2, age);
    return stmt.executeQuery();
}
""".strip(),
        )

        states = {validator.validator_id: validator.state for validator in validators}
        self.assertEqual(states["sql.binding_types"].value, "PASS")

    def test_semantic_validators_fail_for_set_string_on_int_symbol(self) -> None:
        proposal = self.plugin.propose(
            _context(
                file_path="src/main/java/com/example/Foo.java",
                target_method="com.example.Foo.find(int)",
                source="""
public ResultSet find(Connection conn, int age) throws Exception {
    String sql = "SELECT * FROM users WHERE age = " + age;
    Statement stmt = conn.createStatement();
    return stmt.executeQuery(sql);
}
""".strip(),
            )
        )

        validators = self.plugin.evaluate_semantics(
            context={},
            proposal=proposal,
            updated_method_source="""
public ResultSet find(Connection conn, int age) throws Exception {
    String sql = "SELECT * FROM users WHERE age = ?";
    java.sql.PreparedStatement stmt = conn.prepareStatement(sql);
    stmt.setString(1, age);
    return stmt.executeQuery();
}
""".strip(),
        )

        states = {validator.validator_id: validator.state for validator in validators}
        self.assertEqual(states["sql.binding_types"].value, "FAIL")

    def test_semantic_validators_fail_for_set_int_on_string_symbol(self) -> None:
        proposal = self.plugin.propose(
            _context(
                file_path="src/main/java/com/example/Foo.java",
                target_method="com.example.Foo.find(String)",
                source="""
public ResultSet find(Connection conn, String name) throws Exception {
    String sql = "SELECT * FROM users WHERE name = '" + name + "'";
    Statement stmt = conn.createStatement();
    return stmt.executeQuery(sql);
}
""".strip(),
            )
        )

        validators = self.plugin.evaluate_semantics(
            context={},
            proposal=proposal,
            updated_method_source="""
public ResultSet find(Connection conn, String name) throws Exception {
    String sql = "SELECT * FROM users WHERE name = ?";
    java.sql.PreparedStatement stmt = conn.prepareStatement(sql);
    stmt.setInt(1, name);
    return stmt.executeQuery();
}
""".strip(),
        )

        states = {validator.validator_id: validator.state for validator in validators}
        self.assertEqual(states["sql.binding_types"].value, "FAIL")

    def test_semantic_validators_do_not_pass_when_symbol_type_is_unresolved(self) -> None:
        proposal = self.plugin.propose(
            _context(
                file_path="src/main/java/com/example/Foo.java",
                target_method="com.example.Foo.find(String)",
                source="""
public ResultSet find(Connection conn, String name) throws Exception {
    String sql = "SELECT * FROM users WHERE name = '" + name + "'";
    Statement stmt = conn.createStatement();
    return stmt.executeQuery(sql);
}
""".strip(),
            )
        )

        validators = self.plugin.evaluate_semantics(
            context={},
            proposal=proposal,
            updated_method_source="""
public ResultSet find(Connection conn, String name) throws Exception {
    String sql = "SELECT * FROM users WHERE name = ?";
    java.sql.PreparedStatement stmt = conn.prepareStatement(sql);
    stmt.setString(1, missingName);
    return stmt.executeQuery();
}
""".strip(),
        )

        states = {validator.validator_id: validator.state for validator in validators}
        self.assertIn(states["sql.binding_types"].value, {"UNKNOWN", "FAIL"})
        self.assertNotEqual(states["sql.binding_types"].value, "PASS")

    def test_semantic_validators_accept_wrapper_and_primitive_equivalents(self) -> None:
        proposal = self.plugin.propose(
            _context(
                file_path="src/main/java/com/example/Foo.java",
                target_method="com.example.Foo.find(Integer,Boolean,Long)",
                source="""
public ResultSet find(Connection conn, Integer age, Boolean active, Long id) throws Exception {
    String sql = "SELECT * FROM users WHERE age = " + age + " AND active = " + active + " AND id = " + id;
    Statement stmt = conn.createStatement();
    return stmt.executeQuery(sql);
}
""".strip(),
            )
        )

        validators = self.plugin.evaluate_semantics(
            context={},
            proposal=proposal,
            updated_method_source="""
public ResultSet find(Connection conn, Integer age, Boolean active, Long id) throws Exception {
    String sql = "SELECT * FROM users WHERE age = ? AND active = ? AND id = ?";
    java.sql.PreparedStatement stmt = conn.prepareStatement(sql);
    stmt.setInt(1, age);
    stmt.setBoolean(2, active);
    stmt.setLong(3, id);
    return stmt.executeQuery();
}
""".strip(),
        )

        states = {validator.validator_id: validator.state for validator in validators}
        self.assertEqual(states["sql.binding_types"].value, "PASS")

    def test_semantic_validators_fail_for_residual_dynamic_sql_concatenation(self) -> None:
        proposal = self.plugin.propose(
            _context(
                file_path="src/main/java/com/example/Foo.java",
                target_method="com.example.Foo.find(String)",
                source="""
public ResultSet find(Connection conn, String name) throws Exception {
    String sql = "SELECT * FROM users WHERE name = '" + name + "'";
    Statement stmt = conn.createStatement();
    return stmt.executeQuery(sql);
}
""".strip(),
            )
        )

        validators = self.plugin.evaluate_semantics(
            context={},
            proposal=proposal,
            updated_method_source="""
public ResultSet find(Connection conn, String name) throws Exception {
    String sql = "SELECT * FROM users WHERE name = '" + name + "'";
    java.sql.PreparedStatement stmt = conn.prepareStatement(sql + name);
    stmt.setString(1, name);
    return stmt.executeQuery();
}
""".strip(),
        )

        states = {validator.validator_id: validator.state for validator in validators}
        self.assertEqual(states["sql.constant_structure"].value, "FAIL")
        self.assertEqual(states["sql.no_forbidden_dynamic_clause"].value, "FAIL")

    def test_reproducibility_key_is_stable_and_path_normalized(self) -> None:
        source = """
public ResultSet find(Connection conn, String name) throws Exception {
    String sql = \"SELECT * FROM users WHERE name = '\" + name + \"'\";
    Statement stmt = conn.createStatement();
    return stmt.executeQuery(sql);
}
""".strip()
        first = self.plugin.propose(
            _context(
                file_path="/tmp/a/work/src/main/java/com/example/Foo.java",
                target_method="com.example.Foo.find(String)",
                source=source,
            )
        )
        second = self.plugin.propose(
            _context(
                file_path="/private/tmp/b/work/src/main/java/com/example/Foo.java",
                target_method="com.example.Foo.find(String)",
                source=source,
            )
        )

        self.assertEqual(first.details["reproducibility_key"], second.details["reproducibility_key"])
        self.assertEqual(first.details["patch_artifact"], second.details["patch_artifact"])


if __name__ == "__main__":
    unittest.main()