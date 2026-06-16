from __future__ import annotations

import unittest

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
        self.assertEqual(proposal.patch_pattern.pattern_id, "SQL-VAL-001")
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
        self.assertEqual(proposal.patch_pattern.pattern_id, "SQL-VAL-002")
        patch = proposal.details["patch_artifact"]
        self.assertIn("prepareStatement(\"UPDATE users SET active = ? WHERE id = ?\")", patch["edits"][0]["replacement_lines"][0])
        self.assertIn("stmt.setBoolean(1, active);", patch["edits"][1]["replacement_lines"][0])
        self.assertIn("return stmt.executeUpdate();", patch["edits"][1]["replacement_lines"][2])

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