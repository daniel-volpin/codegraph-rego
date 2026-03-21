import tempfile
import unittest
from pathlib import Path

from codegraph.policy.helper_summaries import DirectCallSummaryBuilder
from tests.codegraph.policy._test_helpers import (
    DirectCallTestBase,
    _JAVA_SAFE_CONSTANT,
    _JAVA_SAFE_CONDITIONAL,
    _JAVA_SAFE_RETURN_LITERAL,
    _JAVA_SAFE_RETURN_STRING,
    _JAVA_TAINTED_INDIRECTION,
    _JAVA_TAINTED_PASSTHROUGH,
)


class TestLDAPFilterSinks(DirectCallTestBase):
    def test_safe_helper_return_used_in_ldap_filter(self) -> None:
        result = self._build_summaries(
            current_source=(
                'String param = request.getHeader("x");'
                "String bar = doSomething(param);"
                'String filter = "(&(uid=" + bar + "))";'
            ),
            java_body_lines=_JAVA_SAFE_CONSTANT,
            end_line=4,
        )
        self.assertEqual(result["safe_constant_return_vars"], ["bar"])
        self.assertTrue(result["safe_constant_return_used_in_ldap_filter"])

    def test_tainted_helper_return_used_in_ldap_filter(self) -> None:
        result = self._build_summaries(
            current_source=(
                'String param = request.getHeader("x");'
                "String bar = doSomething(param);"
                'String filter = "(&(uid=" + bar + "))";'
            ),
            java_body_lines=_JAVA_TAINTED_PASSTHROUGH,
        )
        self.assertEqual(result["tainted_return_vars"], ["bar"])
        self.assertTrue(result["tainted_return_used_in_ldap_filter"])

    def test_propagating_helper_with_safe_call_argument_marks_safe_ldap_usage(self) -> None:
        result = self._build_summaries_no_helper(
            current_source=(
                'String param = request.getParameterValues("x")[0];'
                'String safeInput = "barbarians_at_the_gate";'
                "String bar = thing.doSomething(safeInput);"
                'String filter = "(&(uid=" + bar + "))";'
            ),
        )
        self.assertTrue(result["safe_constant_return_used_in_ldap_filter"])
        self.assertFalse(result["tainted_return_used_in_ldap_filter"])

    def test_propagating_helper_with_safe_call_argument_not_marked_tainted(self) -> None:
        result = self._build_summaries(
            current_source=(
                'String param = request.getHeader("x");'
                'String safeInput = "safe";'
                "String bar = doSomething(safeInput);"
                'String filter = "(&(uid=" + bar + "))";'
            ),
            java_body_lines=_JAVA_TAINTED_PASSTHROUGH,
        )
        self.assertEqual(result["tainted_return_vars"], ["bar"])
        self.assertFalse(result["tainted_return_used_in_ldap_filter"])


class TestPathSinks(DirectCallTestBase):
    def test_tainted_helper_return_used_in_path_sink(self) -> None:
        result = self._build_summaries(
            current_source=(
                'String[] values = request.getParameterValues("x");'
                "String param = values[0];"
                "String bar = doSomething(param);"
                "new java.io.File(new java.io.File(org.owasp.benchmark.helpers.Utils.TESTFILES_DIR), bar);"
            ),
            java_body_lines=_JAVA_TAINTED_PASSTHROUGH,
        )
        self.assertEqual(result["tainted_return_vars"], ["bar"])
        self.assertTrue(result["tainted_return_used_in_path_sink"])

    def test_propagating_helper_with_safe_call_argument_marks_safe_path_usage(self) -> None:
        result = self._build_summaries_no_helper(
            current_source=(
                'String param = request.getHeader("x");'
                'String safeInput = "barbarians_at_the_gate";'
                "String bar = thing.doSomething(safeInput);"
                "new java.io.File(bar);"
            ),
        )
        self.assertTrue(result["safe_constant_return_used_in_path_sink"])
        self.assertFalse(result["tainted_return_used_in_path_sink"])

    def test_tainted_helper_return_var_recorded(self) -> None:
        result = self._build_summaries(
            current_source="String bar = doSomething(param);",
            java_body_lines=_JAVA_TAINTED_INDIRECTION,
            end_line=4,
        )
        self.assertEqual(result["tainted_return_vars"], ["bar"])
        self.assertFalse(result["safe_constant_return_used_in_command_sink"])
        self.assertFalse(result["tainted_return_used_in_command_sink"])

    def test_safe_helper_return_used_directly_in_path_sink(self) -> None:
        result = self._build_summaries(
            current_source="String bar = new Helper().doSomething(param); new java.io.File(bar);",
            java_body_lines=_JAVA_SAFE_CONDITIONAL,
            sig="org.example.Inner.doSomething(java.lang.String)",
            fqn="org.example.Inner",
            end_line=5,
        )
        self.assertEqual(result["safe_constant_return_vars"], ["bar"])
        self.assertTrue(result["safe_constant_return_used_in_path_sink"])


class TestCommandExecSinks(DirectCallTestBase):
    def test_tainted_helper_return_used_in_command_payload(self) -> None:
        result = self._build_summaries(
            current_source=(
                'String bar = doSomething(param);'
                'String[] args = new String[] {"sh", "-c", "ls " + bar};'
                "Runtime.getRuntime().exec(args);"
            ),
            java_body_lines=_JAVA_TAINTED_PASSTHROUGH,
        )
        self.assertEqual(result["tainted_return_vars"], ["bar"])
        self.assertTrue(result["tainted_return_used_in_command_sink"])

    def test_safe_helper_return_used_only_in_command_env_not_marked_as_payload(self) -> None:
        result = self._build_summaries(
            current_source=(
                'String bar = doSomething(param);'
                'String cmd = "ls";'
                "String[] argsEnv = {bar};"
                "Runtime.getRuntime().exec(cmd, argsEnv);"
            ),
            java_body_lines=_JAVA_SAFE_RETURN_STRING,
        )
        self.assertEqual(result["safe_constant_return_vars"], ["bar"])
        self.assertTrue(result["safe_constant_return_used_in_command_sink"])

    def test_safe_helper_return_used_in_process_builder_array_payload(self) -> None:
        result = self._build_summaries(
            current_source=(
                "String bar = doSomething(param);"
                'String[] args = new String[] {"sh", "-c", "ls " + bar};'
                "ProcessBuilder pb = new ProcessBuilder();"
                "pb.command(args);"
            ),
            java_body_lines=_JAVA_SAFE_RETURN_STRING,
        )
        self.assertEqual(result["safe_constant_return_vars"], ["bar"])
        self.assertTrue(result["safe_constant_return_used_in_command_sink"])

    def test_tainted_helper_return_used_in_command_env_payload(self) -> None:
        result = self._build_summaries(
            current_source=(
                'String bar = doSomething(param);'
                'String cmd = "ls";'
                "String[] argsEnv = {bar};"
                "Runtime.getRuntime().exec(cmd, argsEnv);"
            ),
            java_body_lines=_JAVA_TAINTED_PASSTHROUGH,
        )
        self.assertEqual(result["tainted_return_vars"], ["bar"])
        self.assertTrue(result["tainted_return_used_in_command_sink"])


class TestXPathSinks(DirectCallTestBase):
    def test_safe_helper_return_used_in_xpath_query(self) -> None:
        result = self._build_summaries(
            current_source=(
                "String bar = doSomething(param);"
                'String expression = "/Employees/Employee[@emplid=\'" + bar + "\']";'
                "xp.evaluate(expression, xmlDocument);"
            ),
            java_body_lines=_JAVA_SAFE_RETURN_LITERAL,
        )
        self.assertEqual(result["safe_constant_return_vars"], ["bar"])
        self.assertTrue(result["safe_constant_return_used_in_xpath_query"])

    def test_tainted_helper_return_used_in_xpath_query(self) -> None:
        result = self._build_summaries(
            current_source=(
                "String bar = doSomething(param);"
                'String expression = "/Employees/Employee[@emplid=\'" + bar + "\']";'
                "xp.compile(expression).evaluate(xmlDocument, javax.xml.xpath.XPathConstants.NODESET);"
            ),
            java_body_lines=_JAVA_TAINTED_PASSTHROUGH,
        )
        self.assertEqual(result["tainted_return_vars"], ["bar"])
        self.assertTrue(result["tainted_return_used_in_xpath_query"])


class TestSQLSinks(DirectCallTestBase):
    def test_safe_helper_return_used_in_sql_query(self) -> None:
        result = self._build_summaries(
            current_source=(
                "String bar = doSomething(param);"
                'String sql = "select * from users where password=\'" + bar + "\'";'
                "connection.prepareStatement(sql);"
            ),
            java_body_lines=_JAVA_SAFE_RETURN_LITERAL,
        )
        self.assertEqual(result["safe_constant_return_vars"], ["bar"])
        self.assertTrue(result["safe_constant_return_used_in_sql_query"])

    def test_tainted_helper_return_used_in_sql_query(self) -> None:
        result = self._build_summaries(
            current_source=(
                "String bar = doSomething(param);"
                'String sql = "select * from users where password=\'" + bar + "\'";'
                "org.owasp.benchmark.helpers.DatabaseHelper.JDBCtemplate.queryForObject(sql, new Object[] {}, String.class);"
            ),
            java_body_lines=_JAVA_TAINTED_PASSTHROUGH,
        )
        self.assertEqual(result["tainted_return_vars"], ["bar"])
        self.assertTrue(result["tainted_return_used_in_sql_query"])


class TestDirectCallSpecialCases(unittest.TestCase):
    """Edge cases: nested class resolution, same-file fallback."""

    def test_prefers_nested_helper_method_over_outer_method_name_collision(self) -> None:
        builder = DirectCallSummaryBuilder()
        with tempfile.TemporaryDirectory() as tmpdir:
            outer_path = Path(tmpdir) / "Outer.java"
            inner_path = Path(tmpdir) / "Inner.java"
            outer_path.write_text(
                "\n".join(
                    [
                        "class Outer {",
                        "  private String doSomething(String param) {",
                        "    return param;",
                        "  }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            inner_path.write_text(
                "\n".join(
                    [
                        "class Outer$Test {",
                        "  private String doSomething(String param) {",
                        '    return "This_should_always_happen";',
                        "  }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            method_snapshot = {
                "class_fqn": "org.example.Outer",
                "calls": [
                    "org.example.Outer.doSomething(java.lang.String)",
                    "org.example.Outer$Test.doSomething(java.lang.String)",
                ],
            }
            method_index = {
                "org.example.Outer.doSomething(java.lang.String)": {
                    "signature": "org.example.Outer.doSomething(java.lang.String)",
                    "class_fqn": "org.example.Outer",
                    "name": "doSomething",
                    "file_path": outer_path.as_posix(),
                    "start_line": 2,
                    "end_line": 3,
                },
                "org.example.Outer$Test.doSomething(java.lang.String)": {
                    "signature": "org.example.Outer$Test.doSomething(java.lang.String)",
                    "class_fqn": "org.example.Outer$Test",
                    "name": "doSomething",
                    "file_path": inner_path.as_posix(),
                    "start_line": 2,
                    "end_line": 3,
                },
            }
            result = builder.build(
                current_source="String bar = new Test().doSomething(param); new java.io.File(bar);",
                method_snapshot=method_snapshot,
                method_index=method_index,
            )

        self.assertEqual(result["safe_constant_return_vars"], ["bar"])
        self.assertTrue(result["safe_constant_return_used_in_path_sink"])

    def test_falls_back_to_same_file_helper_when_call_graph_is_missing(self) -> None:
        builder = DirectCallSummaryBuilder()
        with tempfile.TemporaryDirectory() as tmpdir:
            source_path = Path(tmpdir) / "BenchmarkTest01027.java"
            source_path.write_text(
                "\n".join(
                    [
                        "class BenchmarkTest01027 {",
                        "  void doPost(String param) {",
                        "    String bar = new Test().doSomething(param);",
                        "    new java.io.File(bar);",
                        "  }",
                        "  class Test {",
                        "    String doSomething(String param) {",
                        "      int num = 106;",
                        '      String bar = (7 * 18) + num > 200 ? "This_should_always_happen" : param;',
                        "      return bar;",
                        "    }",
                        "  }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            method_snapshot = {
                "class_fqn": "org.example.BenchmarkTest01027",
                "file_path": source_path.as_posix(),
                "calls": [],
            }
            method_index = {
                "org.example.BenchmarkTest01027$Test.doSomething(java.lang.String)": {
                    "signature": "org.example.BenchmarkTest01027$Test.doSomething(java.lang.String)",
                    "class_fqn": "org.example.BenchmarkTest01027$Test",
                    "name": "doSomething",
                    "file_path": source_path.as_posix(),
                    "start_line": 7,
                    "end_line": 10,
                }
            }
            result = builder.build(
                current_source="String bar = new Test().doSomething(param); new java.io.File(bar);",
                method_snapshot=method_snapshot,
                method_index=method_index,
            )

        self.assertEqual(result["safe_constant_return_vars"], ["bar"])
        self.assertTrue(result["safe_constant_return_used_in_path_sink"])
        self.assertEqual(result["analyzed_call_count"], 1)


if __name__ == "__main__":
    unittest.main()
