import tempfile
import unittest
from pathlib import Path

from codegraph.policy.helper_summaries import DirectCallSummaryBuilder, HelperMethodAnalyzer


class TestHelperMethodAnalyzer(unittest.TestCase):
    def test_marks_safe_constant_return(self) -> None:
        source = (
            "private String doSomething(String param) {"
            'String bar = "safe!";'
            "return bar;"
            "}"
        )
        summary = HelperMethodAnalyzer().summarize(source)
        self.assertTrue(summary.returns_constant_string)
        self.assertFalse(summary.propagates_tainted_input)

    def test_marks_tainted_param_return(self) -> None:
        source = (
            "private String doSomething(String param) {"
            "String bar = param;"
            "return bar;"
            "}"
        )
        summary = HelperMethodAnalyzer().summarize(source)
        self.assertFalse(summary.returns_constant_string)
        self.assertTrue(summary.propagates_tainted_input)

    def test_constant_true_if_else_prefers_tainted_branch(self) -> None:
        source = (
            "private String doSomething(String param) {"
            "String bar;"
            "int num = 196;"
            'if ((500 / 42) + num > 200) bar = param; else bar = "This should never happen";'
            "return bar;"
            "}"
        )
        summary = HelperMethodAnalyzer().summarize(source)
        self.assertFalse(summary.returns_constant_string)
        self.assertTrue(summary.propagates_tainted_input)

    def test_constant_true_if_else_prefers_constant_branch(self) -> None:
        source = (
            "private String doSomething(String param) {"
            "String bar;"
            "int num = 86;"
            'if ((7 * 42) - num > 200) bar = "This_should_always_happen"; else bar = param;'
            "return bar;"
            "}"
        )
        summary = HelperMethodAnalyzer().summarize(source)
        self.assertTrue(summary.returns_constant_string)
        self.assertFalse(summary.propagates_tainted_input)

    def test_map_get_safe_override_is_constant(self) -> None:
        source = (
            "private String doSomething(String param) {"
            'String bar = "safe!";'
            "java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();"
            'map.put("keyA", "a_Value");'
            'map.put("keyB", param);'
            'bar = (String) map.get("keyB");'
            'bar = (String) map.get("keyA");'
            "return bar;"
            "}"
        )
        summary = HelperMethodAnalyzer().summarize(source)
        self.assertTrue(summary.returns_constant_string)
        self.assertFalse(summary.propagates_tainted_input)

    def test_map_get_tainted_value_is_tainted(self) -> None:
        source = (
            "private String doSomething(String param) {"
            'String bar = "safe!";'
            "java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();"
            'map.put("keyA", "a_Value");'
            'map.put("keyB", param);'
            'bar = (String) map.get("keyB");'
            "return bar;"
            "}"
        )
        summary = HelperMethodAnalyzer().summarize(source)
        self.assertFalse(summary.returns_constant_string)
        self.assertTrue(summary.propagates_tainted_input)

    def test_list_safe_tail_value_is_constant(self) -> None:
        source = (
            "private String doSomething(String param) {"
            'String bar = "alsosafe";'
            "java.util.List<String> valuesList = new java.util.ArrayList<String>();"
            'valuesList.add("safe");'
            "valuesList.add(param);"
            'valuesList.add("moresafe");'
            "valuesList.remove(0);"
            "bar = valuesList.get(1);"
            "return bar;"
            "}"
        )
        summary = HelperMethodAnalyzer().summarize(source)
        self.assertTrue(summary.returns_constant_string)
        self.assertFalse(summary.propagates_tainted_input)


class TestDirectCallSummaryBuilder(unittest.TestCase):
    def test_safe_helper_return_used_in_ldap_filter(self) -> None:
        builder = DirectCallSummaryBuilder()
        with tempfile.TemporaryDirectory() as tmpdir:
            callee_path = Path(tmpdir) / "Helper.java"
            callee_source = "\n".join(
                [
                    "class Helper {",
                    "  private String doSomething(String param) {",
                    '    String bar = "safe!";',
                    "    return bar;",
                    "  }",
                    "}",
                ]
            )
            callee_path.write_text(callee_source, encoding="utf-8")
            method_snapshot = {
                "class_fqn": "org.example.Controller",
                "calls": ["org.example.Controller.doSomething(java.lang.String)"],
            }
            method_index = {
                "org.example.Controller.doSomething(java.lang.String)": {
                    "signature": "org.example.Controller.doSomething(java.lang.String)",
                    "class_fqn": "org.example.Controller",
                    "name": "doSomething",
                    "file_path": callee_path.as_posix(),
                    "start_line": 2,
                    "end_line": 4,
                }
            }
            current_source = (
                'String param = request.getHeader("x");'
                "String bar = doSomething(param);"
                'String filter = "(&(uid=" + bar + "))";'
            )
            helper_summaries = builder.build(
                current_source=current_source,
                method_snapshot=method_snapshot,
                method_index=method_index,
            )

        self.assertEqual(helper_summaries["safe_constant_return_vars"], ["bar"])
        self.assertTrue(helper_summaries["safe_constant_return_used_in_ldap_filter"])

    def test_tainted_helper_return_var_recorded(self) -> None:
        builder = DirectCallSummaryBuilder()
        with tempfile.TemporaryDirectory() as tmpdir:
            callee_path = Path(tmpdir) / "Helper.java"
            callee_source = "\n".join(
                [
                    "class Helper {",
                    "  private String doSomething(String param) {",
                    "    String bar = param;",
                    "    return bar;",
                    "  }",
                    "}",
                ]
            )
            callee_path.write_text(callee_source, encoding="utf-8")
            method_snapshot = {
                "class_fqn": "org.example.Controller",
                "calls": ["org.example.Controller.doSomething(java.lang.String)"],
            }
            method_index = {
                "org.example.Controller.doSomething(java.lang.String)": {
                    "signature": "org.example.Controller.doSomething(java.lang.String)",
                    "class_fqn": "org.example.Controller",
                    "name": "doSomething",
                    "file_path": callee_path.as_posix(),
                    "start_line": 2,
                    "end_line": 4,
                }
            }
            helper_summaries = builder.build(
                current_source="String bar = doSomething(param);",
                method_snapshot=method_snapshot,
                method_index=method_index,
            )

        self.assertEqual(helper_summaries["tainted_return_vars"], ["bar"])
        self.assertFalse(helper_summaries["safe_constant_return_used_in_command_sink"])
        self.assertFalse(helper_summaries["tainted_return_used_in_command_sink"])

    def test_safe_helper_return_used_directly_in_path_sink(self) -> None:
        builder = DirectCallSummaryBuilder()
        with tempfile.TemporaryDirectory() as tmpdir:
            callee_path = Path(tmpdir) / "Helper.java"
            callee_source = "\n".join(
                [
                    "class Helper {",
                    "  private String doSomething(String param) {",
                    "    int num = 106;",
                    '    String bar = (7 * 18) + num > 200 ? "This_should_always_happen" : param;',
                    "    return bar;",
                    "  }",
                    "}",
                ]
            )
            callee_path.write_text(callee_source, encoding="utf-8")
            method_snapshot = {
                "class_fqn": "org.example.Controller",
                "calls": ["org.example.Inner.doSomething(java.lang.String)"],
            }
            method_index = {
                "org.example.Inner.doSomething(java.lang.String)": {
                    "signature": "org.example.Inner.doSomething(java.lang.String)",
                    "class_fqn": "org.example.Inner",
                    "name": "doSomething",
                    "file_path": callee_path.as_posix(),
                    "start_line": 2,
                    "end_line": 5,
                }
            }
            helper_summaries = builder.build(
                current_source='String bar = new Helper().doSomething(param); new java.io.File(bar);',
                method_snapshot=method_snapshot,
                method_index=method_index,
            )

        self.assertEqual(helper_summaries["safe_constant_return_vars"], ["bar"])
        self.assertTrue(helper_summaries["safe_constant_return_used_in_path_sink"])

    def test_tainted_helper_return_used_in_command_payload(self) -> None:
        builder = DirectCallSummaryBuilder()
        with tempfile.TemporaryDirectory() as tmpdir:
            callee_path = Path(tmpdir) / "Helper.java"
            callee_source = "\n".join(
                [
                    "class Helper {",
                    "  private String doSomething(String param) {",
                    "    return param;",
                    "  }",
                    "}",
                ]
            )
            callee_path.write_text(callee_source, encoding="utf-8")
            method_snapshot = {
                "class_fqn": "org.example.Controller",
                "calls": ["org.example.Controller.doSomething(java.lang.String)"],
            }
            method_index = {
                "org.example.Controller.doSomething(java.lang.String)": {
                    "signature": "org.example.Controller.doSomething(java.lang.String)",
                    "class_fqn": "org.example.Controller",
                    "name": "doSomething",
                    "file_path": callee_path.as_posix(),
                    "start_line": 2,
                    "end_line": 3,
                }
            }
            helper_summaries = builder.build(
                current_source='String bar = doSomething(param); String[] args = new String[] {"sh", "-c", "ls " + bar}; Runtime.getRuntime().exec(args);',
                method_snapshot=method_snapshot,
                method_index=method_index,
            )

        self.assertEqual(helper_summaries["tainted_return_vars"], ["bar"])
        self.assertTrue(helper_summaries["tainted_return_used_in_command_sink"])

    def test_safe_helper_return_used_in_xpath_query(self) -> None:
        builder = DirectCallSummaryBuilder()
        with tempfile.TemporaryDirectory() as tmpdir:
            callee_path = Path(tmpdir) / "Helper.java"
            callee_source = "\n".join(
                [
                    "class Helper {",
                    "  private String doSomething(String param) {",
                    '    return "safe!";',
                    "  }",
                    "}",
                ]
            )
            callee_path.write_text(callee_source, encoding="utf-8")
            method_snapshot = {
                "class_fqn": "org.example.Controller",
                "calls": ["org.example.Controller.doSomething(java.lang.String)"],
            }
            method_index = {
                "org.example.Controller.doSomething(java.lang.String)": {
                    "signature": "org.example.Controller.doSomething(java.lang.String)",
                    "class_fqn": "org.example.Controller",
                    "name": "doSomething",
                    "file_path": callee_path.as_posix(),
                    "start_line": 2,
                    "end_line": 3,
                }
            }
            helper_summaries = builder.build(
                current_source=(
                    "String bar = doSomething(param);"
                    'String expression = "/Employees/Employee[@emplid=\'" + bar + "\']";'
                    "xp.evaluate(expression, xmlDocument);"
                ),
                method_snapshot=method_snapshot,
                method_index=method_index,
            )

        self.assertEqual(helper_summaries["safe_constant_return_vars"], ["bar"])
        self.assertTrue(helper_summaries["safe_constant_return_used_in_xpath_query"])

    def test_tainted_helper_return_used_in_xpath_query(self) -> None:
        builder = DirectCallSummaryBuilder()
        with tempfile.TemporaryDirectory() as tmpdir:
            callee_path = Path(tmpdir) / "Helper.java"
            callee_source = "\n".join(
                [
                    "class Helper {",
                    "  private String doSomething(String param) {",
                    "    return param;",
                    "  }",
                    "}",
                ]
            )
            callee_path.write_text(callee_source, encoding="utf-8")
            method_snapshot = {
                "class_fqn": "org.example.Controller",
                "calls": ["org.example.Controller.doSomething(java.lang.String)"],
            }
            method_index = {
                "org.example.Controller.doSomething(java.lang.String)": {
                    "signature": "org.example.Controller.doSomething(java.lang.String)",
                    "class_fqn": "org.example.Controller",
                    "name": "doSomething",
                    "file_path": callee_path.as_posix(),
                    "start_line": 2,
                    "end_line": 3,
                }
            }
            helper_summaries = builder.build(
                current_source=(
                    "String bar = doSomething(param);"
                    'String expression = "/Employees/Employee[@emplid=\'" + bar + "\']";'
                    "xp.compile(expression).evaluate(xmlDocument, javax.xml.xpath.XPathConstants.NODESET);"
                ),
                method_snapshot=method_snapshot,
                method_index=method_index,
            )

        self.assertEqual(helper_summaries["tainted_return_vars"], ["bar"])
        self.assertTrue(helper_summaries["tainted_return_used_in_xpath_query"])

    def test_safe_helper_return_used_in_sql_query(self) -> None:
        builder = DirectCallSummaryBuilder()
        with tempfile.TemporaryDirectory() as tmpdir:
            callee_path = Path(tmpdir) / "Helper.java"
            callee_source = "\n".join(
                [
                    "class Helper {",
                    "  private String doSomething(String param) {",
                    '    return "safe!";',
                    "  }",
                    "}",
                ]
            )
            callee_path.write_text(callee_source, encoding="utf-8")
            method_snapshot = {
                "class_fqn": "org.example.Controller",
                "calls": ["org.example.Controller.doSomething(java.lang.String)"],
            }
            method_index = {
                "org.example.Controller.doSomething(java.lang.String)": {
                    "signature": "org.example.Controller.doSomething(java.lang.String)",
                    "class_fqn": "org.example.Controller",
                    "name": "doSomething",
                    "file_path": callee_path.as_posix(),
                    "start_line": 2,
                    "end_line": 3,
                }
            }
            helper_summaries = builder.build(
                current_source=(
                    "String bar = doSomething(param);"
                    'String sql = "select * from users where password=\'" + bar + "\'";'
                    "connection.prepareStatement(sql);"
                ),
                method_snapshot=method_snapshot,
                method_index=method_index,
            )

        self.assertEqual(helper_summaries["safe_constant_return_vars"], ["bar"])
        self.assertTrue(helper_summaries["safe_constant_return_used_in_sql_query"])

    def test_tainted_helper_return_used_in_sql_query(self) -> None:
        builder = DirectCallSummaryBuilder()
        with tempfile.TemporaryDirectory() as tmpdir:
            callee_path = Path(tmpdir) / "Helper.java"
            callee_source = "\n".join(
                [
                    "class Helper {",
                    "  private String doSomething(String param) {",
                    "    return param;",
                    "  }",
                    "}",
                ]
            )
            callee_path.write_text(callee_source, encoding="utf-8")
            method_snapshot = {
                "class_fqn": "org.example.Controller",
                "calls": ["org.example.Controller.doSomething(java.lang.String)"],
            }
            method_index = {
                "org.example.Controller.doSomething(java.lang.String)": {
                    "signature": "org.example.Controller.doSomething(java.lang.String)",
                    "class_fqn": "org.example.Controller",
                    "name": "doSomething",
                    "file_path": callee_path.as_posix(),
                    "start_line": 2,
                    "end_line": 3,
                }
            }
            helper_summaries = builder.build(
                current_source=(
                    "String bar = doSomething(param);"
                    'String sql = "select * from users where password=\'" + bar + "\'";'
                    "org.owasp.benchmark.helpers.DatabaseHelper.JDBCtemplate.queryForObject(sql, new Object[] {}, String.class);"
                ),
                method_snapshot=method_snapshot,
                method_index=method_index,
            )

        self.assertEqual(helper_summaries["tainted_return_vars"], ["bar"])
        self.assertTrue(helper_summaries["tainted_return_used_in_sql_query"])

    def test_safe_helper_return_used_only_in_command_env_not_marked_as_payload(self) -> None:
        builder = DirectCallSummaryBuilder()
        with tempfile.TemporaryDirectory() as tmpdir:
            callee_path = Path(tmpdir) / "Helper.java"
            callee_source = "\n".join(
                [
                    "class Helper {",
                    "  private String doSomething(String param) {",
                    '    return "safe";',
                    "  }",
                    "}",
                ]
            )
            callee_path.write_text(callee_source, encoding="utf-8")
            method_snapshot = {
                "class_fqn": "org.example.Controller",
                "calls": ["org.example.Controller.doSomething(java.lang.String)"],
            }
            method_index = {
                "org.example.Controller.doSomething(java.lang.String)": {
                    "signature": "org.example.Controller.doSomething(java.lang.String)",
                    "class_fqn": "org.example.Controller",
                    "name": "doSomething",
                    "file_path": callee_path.as_posix(),
                    "start_line": 2,
                    "end_line": 3,
                }
            }
            helper_summaries = builder.build(
                current_source='String bar = doSomething(param); String cmd = "ls"; String[] argsEnv = {bar}; Runtime.getRuntime().exec(cmd, argsEnv);',
                method_snapshot=method_snapshot,
                method_index=method_index,
            )

        self.assertEqual(helper_summaries["safe_constant_return_vars"], ["bar"])
        self.assertTrue(helper_summaries["safe_constant_return_used_in_command_sink"])

    def test_safe_helper_return_used_in_process_builder_array_payload(self) -> None:
        builder = DirectCallSummaryBuilder()
        with tempfile.TemporaryDirectory() as tmpdir:
            callee_path = Path(tmpdir) / "Helper.java"
            callee_source = "\n".join(
                [
                    "class Helper {",
                    "  private String doSomething(String param) {",
                    '    return "safe";',
                    "  }",
                    "}",
                ]
            )
            callee_path.write_text(callee_source, encoding="utf-8")
            method_snapshot = {
                "class_fqn": "org.example.Controller",
                "calls": ["org.example.Controller.doSomething(java.lang.String)"],
            }
            method_index = {
                "org.example.Controller.doSomething(java.lang.String)": {
                    "signature": "org.example.Controller.doSomething(java.lang.String)",
                    "class_fqn": "org.example.Controller",
                    "name": "doSomething",
                    "file_path": callee_path.as_posix(),
                    "start_line": 2,
                    "end_line": 3,
                }
            }
            helper_summaries = builder.build(
                current_source=(
                    'String bar = doSomething(param);'
                    'String[] args = new String[] {"sh", "-c", "ls " + bar};'
                    "ProcessBuilder pb = new ProcessBuilder();"
                    "pb.command(args);"
                ),
                method_snapshot=method_snapshot,
                method_index=method_index,
            )

        self.assertEqual(helper_summaries["safe_constant_return_vars"], ["bar"])
        self.assertTrue(helper_summaries["safe_constant_return_used_in_command_sink"])

    def test_tainted_helper_return_used_in_command_env_payload(self) -> None:
        builder = DirectCallSummaryBuilder()
        with tempfile.TemporaryDirectory() as tmpdir:
            callee_path = Path(tmpdir) / "Helper.java"
            callee_source = "\n".join(
                [
                    "class Helper {",
                    "  private String doSomething(String param) {",
                    "    return param;",
                    "  }",
                    "}",
                ]
            )
            callee_path.write_text(callee_source, encoding="utf-8")
            method_snapshot = {
                "class_fqn": "org.example.Controller",
                "calls": ["org.example.Controller.doSomething(java.lang.String)"],
            }
            method_index = {
                "org.example.Controller.doSomething(java.lang.String)": {
                    "signature": "org.example.Controller.doSomething(java.lang.String)",
                    "class_fqn": "org.example.Controller",
                    "name": "doSomething",
                    "file_path": callee_path.as_posix(),
                    "start_line": 2,
                    "end_line": 3,
                }
            }
            helper_summaries = builder.build(
                current_source='String bar = doSomething(param); String cmd = "ls"; String[] argsEnv = {bar}; Runtime.getRuntime().exec(cmd, argsEnv);',
                method_snapshot=method_snapshot,
                method_index=method_index,
            )

        self.assertEqual(helper_summaries["tainted_return_vars"], ["bar"])
        self.assertTrue(helper_summaries["tainted_return_used_in_command_sink"])

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
            helper_summaries = builder.build(
                current_source='String bar = new Test().doSomething(param); new java.io.File(bar);',
                method_snapshot=method_snapshot,
                method_index=method_index,
            )

        self.assertEqual(helper_summaries["safe_constant_return_vars"], ["bar"])
        self.assertTrue(helper_summaries["safe_constant_return_used_in_path_sink"])

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
            helper_summaries = builder.build(
                current_source='String bar = new Test().doSomething(param); new java.io.File(bar);',
                method_snapshot=method_snapshot,
                method_index=method_index,
            )

        self.assertEqual(helper_summaries["safe_constant_return_vars"], ["bar"])
        self.assertTrue(helper_summaries["safe_constant_return_used_in_path_sink"])
        self.assertEqual(helper_summaries["analyzed_call_count"], 1)


if __name__ == "__main__":
    unittest.main()
