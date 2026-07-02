import unittest

from codegraph.policy.source_analysis import analyze_policy_indicators


class TestCommandInjectionDetected(unittest.TestCase):
    def test_command_injection_detected(self) -> None:
        source = 'String cmd = "echo " + request.getHeader("x"); new ProcessBuilder().command(cmd);'
        flags = analyze_policy_indicators(source)
        self.assertTrue(flags["command_exec_string_tainted"])
        self.assertFalse(flags["command_exec_args_tainted"])
        self.assertFalse(flags["command_env_only_tainted"])
        self.assertTrue(flags["command_injection_detected"])

    def test_command_injection_builder_detected(self) -> None:
        source = (
            'StringBuilder cmd = new StringBuilder("echo ");'
            'cmd.append(request.getHeader("x"));'
            "Runtime.getRuntime().exec(cmd.toString());"
        )
        flags = analyze_policy_indicators(source)
        self.assertTrue(flags["command_exec_string_tainted"])
        self.assertTrue(flags["command_injection_detected"])

    def test_command_injection_exec_args_detected(self) -> None:
        source = (
            'String input = request.getHeader("x");'
            'String[] args = new String[] {"sh", "-c", "ls " + input};'
            "Runtime.getRuntime().exec(args);"
        )
        flags = analyze_policy_indicators(source)
        self.assertFalse(flags["command_exec_string_tainted"])
        self.assertTrue(flags["command_exec_args_tainted"])
        self.assertTrue(flags["command_injection_detected"])

    def test_command_injection_process_builder_list_detected(self) -> None:
        source = (
            'java.util.Enumeration<String> headers = request.getHeaders("x");'
            "String param = headers.nextElement();"
            "java.util.List<String> argList = new java.util.ArrayList<String>();"
            'argList.add("sh");'
            'argList.add("-c");'
            'argList.add("echo " + param);'
            "ProcessBuilder pb = new ProcessBuilder();"
            "pb.command(argList);"
        )
        flags = analyze_policy_indicators(source)
        self.assertTrue(flags["command_exec_args_tainted"])
        self.assertTrue(flags["command_injection_detected"])

    def test_command_injection_conditional_list_payload_detected(self) -> None:
        source = (
            'String param = request.getParameter("x");'
            'String bar = "";'
            "if (param != null) {"
            "java.util.List<String> valuesList = new java.util.ArrayList<String>();"
            'valuesList.add("safe");'
            "valuesList.add(param);"
            'valuesList.add("moresafe");'
            "valuesList.remove(0);"
            "bar = valuesList.get(0);"
            "}"
            'String[] args = new String[] {"sh", "-c", "ls " + bar};'
            "Runtime.getRuntime().exec(args);"
        )
        flags = analyze_policy_indicators(source)
        self.assertTrue(flags["command_exec_args_tainted"])
        self.assertTrue(flags["command_injection_detected"])

    def test_command_injection_runtime_exec_args_with_get_the_parameter_detected(self) -> None:
        source = (
            "org.owasp.benchmark.helpers.SeparateClassRequest scr = new org.owasp.benchmark.helpers.SeparateClassRequest(request);"
            'String param = scr.getTheParameter("x");'
            'String[] args = new String[] {"sh", "-c", "ls " + param};'
            'String[] argsEnv = {"foo=bar"};'
            "Runtime.getRuntime().exec(args, argsEnv);"
        )
        flags = analyze_policy_indicators(source)
        self.assertTrue(flags["command_exec_args_tainted"])
        self.assertFalse(flags["command_env_only_tainted"])
        self.assertTrue(flags["command_injection_detected"])

    def test_command_injection_base64_roundtrip_detected(self) -> None:
        source = (
            'String[] values = request.getParameterValues("x");'
            "String param = values[0];"
            "String bar = new String(org.apache.commons.codec.binary.Base64.decodeBase64(org.apache.commons.codec.binary.Base64.encodeBase64(param.getBytes())));"
            'String cmd = "echo " + bar;'
            "Runtime.getRuntime().exec(cmd);"
        )
        flags = analyze_policy_indicators(source)
        self.assertTrue(flags["command_exec_string_tainted"])
        self.assertTrue(flags["command_injection_detected"])

    def test_command_injection_conditional_base64_roundtrip_detected(self) -> None:
        source = (
            'String[] values = request.getParameterValues("x");'
            "String param = values[0];"
            'String bar = "";'
            "if (param != null) {"
            "bar = new String(org.apache.commons.codec.binary.Base64.decodeBase64(org.apache.commons.codec.binary.Base64.encodeBase64(param.getBytes())));"
            "}"
            'String cmd = "echo " + bar;'
            "Runtime.getRuntime().exec(cmd);"
        )
        flags = analyze_policy_indicators(source)
        self.assertTrue(flags["command_exec_string_tainted"])
        self.assertTrue(flags["command_injection_detected"])

    def test_command_env_only_taint_not_detected(self) -> None:
        source = (
            'String param = request.getParameter("x");'
            'String cmd = "ls";'
            "String[] argsEnv = {param};"
            "Runtime.getRuntime().exec(cmd, argsEnv);"
        )
        flags = analyze_policy_indicators(source)
        self.assertFalse(flags["command_exec_string_tainted"])
        self.assertFalse(flags["command_exec_args_tainted"])
        self.assertTrue(flags["command_env_only_tainted"])
        self.assertFalse(flags["command_injection_detected"])

    def test_command_switch_fallthrough_args_detected(self) -> None:
        source = (
            'String param = request.getParameter("x");'
            'String guess = "ABC";'
            "char switchTarget = guess.charAt(2);"
            "String bar;"
            "switch (switchTarget) { case 'A': bar = param; break; case 'B': bar = \"safe\"; break; case 'C': case 'D': bar = param; break; default: bar = \"safe\"; break; }"
            'String[] args = {"sh", "-c", "ls " + bar};'
            'String[] argsEnv = {"foo=bar"};'
            'Runtime.getRuntime().exec(args, argsEnv, new java.io.File(System.getProperty("user.dir")));'
        )
        flags = analyze_policy_indicators(source)
        self.assertFalse(flags["command_exec_string_tainted"])
        self.assertTrue(flags["command_exec_args_tainted"])
        self.assertTrue(flags["command_injection_detected"])


class TestCommandInjectionNotFlagged(unittest.TestCase):
    def test_command_constant_if_else_safe_branch_not_flagged(self) -> None:
        source = (
            'String param = request.getHeaders("x").nextElement();'
            'param = java.net.URLDecoder.decode(param, "UTF-8");'
            "String bar;"
            "int num = 86;"
            'if ((7 * 42) - num > 200) bar = "This_should_always_happen"; else bar = param;'
            'String cmd = "echo ";'
            'String[] argsEnv = {"Foo=bar"};'
            "Runtime.getRuntime().exec(cmd + bar, argsEnv);"
        )
        flags = analyze_policy_indicators(source)
        self.assertFalse(flags["command_exec_string_tainted"])
        self.assertFalse(flags["command_exec_args_tainted"])
        self.assertFalse(flags["command_injection_detected"])

    def test_command_safe_branch_not_poisoned_by_comments_or_annotations(self) -> None:
        source = (
            '/** comment with href = request.getHeader(\\"x\\") */'
            '@WebServlet(value = "/cmdi-safe") '
            "public class Demo {"
            "  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {"
            '    String param = request.getHeaders("x").nextElement();'
            "    String bar;"
            "    int num = 86;"
            '    if ((7 * 42) - num > 200) bar = "This_should_always_happen"; else bar = param;'
            '    String[] argsEnv = {"Foo=bar"};'
            '    Runtime.getRuntime().exec("echo " + bar, argsEnv);'
            "  }"
            "}"
        )
        flags = analyze_policy_indicators(source)
        self.assertFalse(flags["command_exec_string_tainted"])
        self.assertFalse(flags["command_exec_args_tainted"])
        self.assertFalse(flags["command_injection_detected"])

    def test_command_map_safe_override_after_nullable_source_not_flagged(self) -> None:
        source = (
            'String[] values = request.getParameterValues("BenchmarkTest00742");'
            "String param;"
            "if (values != null && values.length > 0) param = values[0];"
            'else param = "";'
            'String bar = "safe!";'
            "java.util.HashMap<String, Object> map62435 = new java.util.HashMap<String, Object>();"
            'map62435.put("keyA-62435", "a_Value");'
            'map62435.put("keyB-62435", param);'
            'map62435.put("keyC", "another_Value");'
            'bar = (String) map62435.get("keyB-62435");'
            'bar = (String) map62435.get("keyA-62435");'
            'String cmd = "";'
            'String osName = System.getProperty("os.name");'
            'if (osName.indexOf("Windows") != -1) {'
            'cmd = org.owasp.benchmark.helpers.Utils.getOSCommandString("echo");'
            "}"
            'String[] argsEnv = {"Foo=bar"};'
            'Runtime.getRuntime().exec(cmd + bar, argsEnv, new java.io.File(System.getProperty("user.dir")));'
        )
        flags = analyze_policy_indicators(source)
        self.assertFalse(flags["command_exec_string_tainted"])
        self.assertFalse(flags["command_exec_args_tainted"])
        self.assertFalse(flags["command_injection_detected"])

    def test_command_branch_taint_not_cleared_by_optional_safe_reassignment(self) -> None:
        source = 'String cmd = request.getParameter("cmd");if (flag) cmd = "safe";Runtime.getRuntime().exec(cmd);'
        flags = analyze_policy_indicators(source)
        self.assertTrue(flags["command_exec_string_tainted"])
        self.assertTrue(flags["command_injection_detected"])


class TestLDAPInjection(unittest.TestCase):
    def test_ldap_injection_detected(self) -> None:
        source = 'String filter = "(&(uid=" + request.getHeader("x") + "))"; InitialDirContext idc = null; idc.search(base, filter, filters, sc);'
        flags = analyze_policy_indicators(source)
        self.assertTrue(flags["ldap_injection_detected"])

    def test_ldap_injection_get_headers_detected(self) -> None:
        source = (
            'java.util.Enumeration<String> headers = request.getHeaders("x");'
            "String param = headers.nextElement();"
            'String filter = "(&(uid=" + param + "))";'
            "InitialDirContext idc = null; idc.search(base, filter, filters, sc);"
        )
        flags = analyze_policy_indicators(source)
        self.assertTrue(flags["ldap_injection_detected"])

    def test_ldap_injection_get_parameter_values_detected(self) -> None:
        source = (
            'String[] values = request.getParameterValues("x");'
            "String bar = values[0];"
            'String filter = "(&(uid=" + bar + "))";'
            "InitialDirContext idc = null; idc.search(base, filter, sc);"
        )
        flags = analyze_policy_indicators(source)
        self.assertTrue(flags["ldap_injection_detected"])

    def test_ldap_safe_constant_ternary_not_flagged(self) -> None:
        source = (
            'String param = request.getHeader("x");'
            "int num = 106;"
            'String bar = (7 * 18) + num > 200 ? "This_should_always_happen" : param;'
            'String filter = "(&(uid=" + bar + "))";'
            "InitialDirContext idc = null; idc.search(base, filter, filters, sc);"
        )
        flags = analyze_policy_indicators(source)
        self.assertFalse(flags["ldap_injection_detected"])
        self.assertTrue(flags["ldap_filter_uses_safe_constant"])

    def test_ldap_safe_constant_switch_not_flagged(self) -> None:
        source = (
            'String param = request.getHeader("x");'
            'String guess = "ABC";'
            "char switchTarget = guess.charAt(1);"
            "String bar = param;"
            "switch (switchTarget) { case 'A': bar = param; break; case 'B': bar = \"bob\"; break; case 'C': case 'D': bar = param; break; default: bar = \"bob's your uncle\"; break; }"
            'String filter = "(&(uid=" + bar + "))";'
            "InitialDirContext idc = null; idc.search(base, filter, sc);"
        )
        flags = analyze_policy_indicators(source)
        self.assertFalse(flags["ldap_injection_detected"])
        self.assertTrue(flags["ldap_filter_uses_safe_constant"])


class TestXPathInjection(unittest.TestCase):
    def test_xpath_injection_detected(self) -> None:
        source = 'String expr = "/Employees/Employee[@emplid=\'" + request.getHeader("x") + "\']"; XPathFactory.newInstance(); xp.evaluate(expr, xmlDocument);'
        flags = analyze_policy_indicators(source)
        self.assertTrue(flags["xpath_injection_detected"])

    def test_xpath_injection_builder_detected(self) -> None:
        source = (
            'StringBuilder expr = new StringBuilder("/Employees/Employee[@emplid=\'");'
            'expr.append(request.getHeader("x"));'
            'expr.append("\']"); XPathFactory.newInstance(); xp.evaluate(expr.toString(), xmlDocument);'
        )
        flags = analyze_policy_indicators(source)
        self.assertTrue(flags["xpath_injection_detected"])

    def test_xpath_constant_if_else_safe_branch_not_flagged(self) -> None:
        source = (
            'String param = request.getHeader("x");'
            "String bar;"
            "int num = 86;"
            'if ((7 * 42) - num > 200) bar = "This_should_always_happen"; else bar = param;'
            'String expression = "/Employees/Employee[@emplid=\'" + bar + "\']";'
            "XPathFactory.newInstance(); xp.evaluate(expression, xmlDocument);"
        )
        flags = analyze_policy_indicators(source)
        self.assertFalse(flags["xpath_injection_detected"])
        self.assertTrue(flags["xpath_query_uses_safe_constant"])

    def test_xpath_map_safe_override_not_flagged(self) -> None:
        source = (
            'String param = request.getHeader("x");'
            'String bar = "safe!";'
            "java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();"
            'map.put("keyA", "a_Value");'
            'map.put("keyB", param);'
            'bar = (String) map.get("keyB");'
            'bar = (String) map.get("keyA");'
            'String expression = "/Employees/Employee[@emplid=\'" + bar + "\']";'
            "XPathFactory.newInstance(); xp.compile(expression).evaluate(xmlDocument, javax.xml.xpath.XPathConstants.NODESET);"
        )
        flags = analyze_policy_indicators(source)
        self.assertFalse(flags["xpath_injection_detected"])
        self.assertTrue(flags["xpath_query_uses_safe_constant"])

    def test_xpath_safe_get_the_value_source_not_flagged(self) -> None:
        source = (
            "org.owasp.benchmark.helpers.SeparateClassRequest scr = new org.owasp.benchmark.helpers.SeparateClassRequest(request);"
            'String param = scr.getTheValue("BenchmarkTest00941");'
            'String bar = "";'
            "if (param != null) {"
            "bar = new String(org.apache.commons.codec.binary.Base64.decodeBase64(org.apache.commons.codec.binary.Base64.encodeBase64(param.getBytes())));"
            "}"
            'java.io.FileInputStream file = new java.io.FileInputStream(org.owasp.benchmark.helpers.Utils.getFileFromClasspath("employees.xml", this.getClass().getClassLoader()));'
            "XPathFactory.newInstance();"
            'String expression = "/Employees/Employee[@emplid=\'" + bar + "\']";'
            "xp.compile(expression).evaluate(xmlDocument, javax.xml.xpath.XPathConstants.NODESET);"
        )
        flags = analyze_policy_indicators(source)
        self.assertFalse(flags["xpath_injection_detected"])
        self.assertFalse(flags["xpath_query_uses_tainted_input"])


class TestSQLInjection(unittest.TestCase):
    def test_sql_dynamic_query_detected(self) -> None:
        source = (
            'StringBuilder sql = new StringBuilder("select * from users where name = \'");'
            'sql.append(request.getHeader("x"));'
            'sql.append("\'"); connection.prepareCall(sql.toString());'
        )
        flags = analyze_policy_indicators(source)
        self.assertTrue(flags["sql_dynamic_query_detected"])
        self.assertTrue(flags["sql_query_uses_tainted_input"])

    def test_sql_dynamic_query_jdbc_template_detected(self) -> None:
        source = (
            'String[] values = request.getParameterMap().get("x");'
            'String sql = "select * from users where name = \'" + values[0] + "\'";'
            "org.owasp.benchmark.helpers.DatabaseHelper.JDBCtemplate.queryForRowSet(sql);"
        )
        flags = analyze_policy_indicators(source)
        self.assertTrue(flags["sql_dynamic_query_detected"])

    def test_sql_dynamic_query_prepare_statement_detected(self) -> None:
        source = (
            'String[] values = request.getParameterValues("x");'
            'String sql = "select * from users where username=? and password=\'" + values[0] + "\'";'
            "connection.prepareStatement(sql);"
        )
        flags = analyze_policy_indicators(source)
        self.assertTrue(flags["sql_dynamic_query_detected"])

    def test_sql_dynamic_query_query_for_object_detected(self) -> None:
        source = (
            'String param = request.getHeader("x");'
            'String sql = "select * from users where password=\'" + param + "\'";'
            "org.owasp.benchmark.helpers.DatabaseHelper.JDBCtemplate.queryForObject(sql, new Object[] {}, String.class);"
        )
        flags = analyze_policy_indicators(source)
        self.assertTrue(flags["sql_dynamic_query_detected"])
        self.assertTrue(flags["sql_query_uses_tainted_input"])

    def test_sql_dynamic_query_batch_update_detected(self) -> None:
        source = (
            'String param = request.getHeader("x");'
            'String sql = "update users set password=\'" + param + "\'";'
            "org.owasp.benchmark.helpers.DatabaseHelper.JDBCtemplate.batchUpdate(sql);"
        )
        flags = analyze_policy_indicators(source)
        self.assertTrue(flags["sql_dynamic_query_detected"])
        self.assertTrue(flags["sql_query_uses_tainted_input"])

    def test_sql_constant_ternary_safe_branch_not_flagged(self) -> None:
        source = (
            'String param = request.getHeader("x");'
            "int num = 106;"
            'String bar = (7 * 18) + num > 200 ? "This_should_always_happen" : param;'
            "String sql = \"insert into users (username, password) values ('foo', '\" + bar + \"')\";"
            "statement.executeUpdate(sql);"
        )
        flags = analyze_policy_indicators(source)
        self.assertFalse(flags["sql_dynamic_query_detected"])
        self.assertTrue(flags["sql_query_uses_safe_constant"])

    def test_sql_map_safe_override_not_flagged(self) -> None:
        source = (
            'String param = request.getHeader("x");'
            'String bar = "safe!";'
            "java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();"
            'map.put("keyA", "a_Value");'
            'map.put("keyB", param);'
            'bar = (String) map.get("keyB");'
            'bar = (String) map.get("keyA");'
            'String sql = "select * from users where password=\'" + bar + "\'";'
            "connection.prepareStatement(sql);"
        )
        flags = analyze_policy_indicators(source)
        self.assertFalse(flags["sql_dynamic_query_detected"])
        self.assertTrue(flags["sql_query_uses_safe_constant"])

    def test_sql_list_safe_override_not_flagged(self) -> None:
        source = (
            "org.owasp.benchmark.helpers.SeparateClassRequest scr = new org.owasp.benchmark.helpers.SeparateClassRequest(request);"
            'String param = scr.getTheValue("BenchmarkTest00931");'
            'String bar = "alsosafe";'
            "if (param != null) {"
            "java.util.List<String> valuesList = new java.util.ArrayList<String>();"
            'valuesList.add("safe");'
            "valuesList.add(param);"
            'valuesList.add("moresafe");'
            "valuesList.remove(0);"
            "bar = valuesList.get(1);"
            "}"
            "String sql = \"SELECT * from USERS where USERNAME='foo' and PASSWORD='\" + bar + \"'\";"
            "org.owasp.benchmark.helpers.DatabaseHelper.JDBCtemplate.execute(sql);"
        )
        flags = analyze_policy_indicators(source)
        self.assertFalse(flags["sql_dynamic_query_detected"])
        self.assertFalse(flags["sql_query_uses_tainted_input"])

    def test_sql_branch_taint_not_cleared_by_optional_safe_reassignment(self) -> None:
        source = (
            'String param = request.getParameter("x");'
            "String bar = param;"
            'if (flag) bar = "safe";'
            "String sql = \"SELECT * from USERS where USERNAME='foo' and PASSWORD='\" + bar + \"'\";"
            "connection.prepareStatement(sql);"
        )
        flags = analyze_policy_indicators(source)
        self.assertTrue(flags["sql_query_uses_tainted_input"])
        self.assertTrue(flags["sql_dynamic_query_detected"])

    def test_sql_prepare_call_flags(self) -> None:
        source = "java.sql.CallableStatement statement = connection.prepareCall(sql);"
        flags = analyze_policy_indicators(source)
        self.assertTrue(flags["sql_prepare_call_detected"])
        self.assertTrue(flags["sql_callable_statement_detected"])

    def test_sql_cookie_decode_query_for_map_detected(self) -> None:
        source = (
            "javax.servlet.http.Cookie[] theCookies = request.getCookies();"
            'String param = "noCookieValueSupplied";'
            "if (theCookies != null) { for (javax.servlet.http.Cookie theCookie : theCookies) {"
            'if (theCookie.getName().equals("BenchmarkTest00102")) {'
            'param = java.net.URLDecoder.decode(theCookie.getValue(), "UTF-8");'
            "break; } } }"
            "String bar = param;"
            "String sql = \"SELECT * from USERS where USERNAME='foo' and PASSWORD='\" + bar + \"'\";"
            "org.owasp.benchmark.helpers.DatabaseHelper.JDBCtemplate.queryForMap(sql);"
        )
        flags = analyze_policy_indicators(source)
        self.assertTrue(flags["sql_query_uses_tainted_input"])
        self.assertTrue(flags["sql_dynamic_query_detected"])

    def test_sql_if_else_nullable_values_branch_detected(self) -> None:
        source = (
            'String[] values = request.getParameterValues("x");'
            "String param;"
            'if (values != null && values.length > 0) param = values[0]; else param = "";'
            "String bar = param;"
            "String sql = \"SELECT * from USERS where USERNAME='foo' and PASSWORD='\" + bar + \"'\";"
            "org.owasp.benchmark.helpers.DatabaseHelper.JDBCtemplate.queryForObject(sql, Long.class);"
        )
        flags = analyze_policy_indicators(source)
        self.assertTrue(flags["sql_query_uses_tainted_input"])
        self.assertTrue(flags["sql_dynamic_query_detected"])

    def test_sql_add_batch_sink_detected(self) -> None:
        source = (
            'String param = request.getHeader("x");'
            "String sql = \"SELECT * from USERS where USERNAME='foo' and PASSWORD='\" + param + \"'\";"
            "java.sql.Statement statement = org.owasp.benchmark.helpers.DatabaseHelper.getSqlStatement();"
            "statement.addBatch(sql);"
            "statement.executeBatch();"
        )
        flags = analyze_policy_indicators(source)
        self.assertTrue(flags["sql_query_uses_tainted_input"])
        self.assertTrue(flags["sql_dynamic_query_detected"])


if __name__ == "__main__":
    unittest.main()
