import unittest

from codegraph.policy.source_analysis import analyze_crypto_indicators


class TestSourceAnalysis(unittest.TestCase):
    def test_md5_literal(self) -> None:
        source = 'MessageDigest.getInstance("MD5");'
        flags = analyze_crypto_indicators(source)
        self.assertTrue(flags["md5_detected"])

    def test_md5_variable(self) -> None:
        source = 'String algo = "MD5"; MessageDigest.getInstance(algo);'
        flags = analyze_crypto_indicators(source)
        self.assertTrue(flags["md5_detected"])
        self.assertTrue(flags["md5_variable"])

    def test_weak_cipher_des(self) -> None:
        source = 'Cipher.getInstance("DES");'
        flags = analyze_crypto_indicators(source)
        self.assertTrue(flags["weak_cipher_detected"])

    def test_weak_cipher_rc4(self) -> None:
        source = 'Cipher.getInstance("RC4");'
        flags = analyze_crypto_indicators(source)
        self.assertTrue(flags["weak_cipher_detected"])

    def test_weak_cipher_ecb(self) -> None:
        source = 'Cipher.getInstance("AES/ECB/PKCS5Padding");'
        flags = analyze_crypto_indicators(source)
        self.assertTrue(flags["weak_cipher_detected"])

    def test_safe_cipher_not_flagged(self) -> None:
        source = 'Cipher.getInstance("AES/GCM/NoPadding");'
        flags = analyze_crypto_indicators(source)
        self.assertFalse(flags["weak_cipher_detected"])

    def test_insecure_random_constructor_detected(self) -> None:
        source = "int token = new java.util.Random().nextInt();"
        flags = analyze_crypto_indicators(source)
        self.assertTrue(flags["insecure_random_detected"])
        self.assertFalse(flags["sha1prng_detected"])

    def test_sha1prng_detected(self) -> None:
        source = 'double value = java.security.SecureRandom.getInstance("SHA1PRNG").nextDouble();'
        flags = analyze_crypto_indicators(source)
        self.assertFalse(flags["insecure_random_detected"])
        self.assertTrue(flags["sha1prng_detected"])

    def test_math_random_string_literal_not_flagged(self) -> None:
        source = 'response.getWriter().println("Weak Randomness Test java.lang.Math.random() executed");'
        flags = analyze_crypto_indicators(source)
        self.assertFalse(flags["insecure_random_detected"])

    def test_math_random_comment_not_flagged(self) -> None:
        source = "// java.lang.Math.random() should not trigger here\nint x = 1;"
        flags = analyze_crypto_indicators(source)
        self.assertFalse(flags["insecure_random_detected"])

    def test_path_traversal_detected(self) -> None:
        source = 'String fileName = base + request.getHeader("x"); new java.io.FileInputStream(new java.io.File(fileName));'
        flags = analyze_crypto_indicators(source)
        self.assertTrue(flags["path_traversal_detected"])

    def test_path_traversal_file_output_stream_detected(self) -> None:
        source = (
            'String value = request.getHeader("x");'
            'String fileName = base + value;'
            "new java.io.FileOutputStream(fileName, false);"
        )
        flags = analyze_crypto_indicators(source)
        self.assertTrue(flags["path_traversal_detected"])

    def test_path_traversal_two_arg_file_detected(self) -> None:
        source = 'String bar = request.getHeader("x"); new java.io.File(bar, "/Test.txt");'
        flags = analyze_crypto_indicators(source)
        self.assertTrue(flags["path_traversal_detected"])

    def test_path_traversal_get_parameter_map_detected(self) -> None:
        source = (
            'java.util.Map<String, String[]> map = request.getParameterMap();'
            'String[] values = map.get("x");'
            'String param = values[0];'
            'String fileName = base + param;'
            "new java.io.FileOutputStream(fileName, false);"
        )
        flags = analyze_crypto_indicators(source)
        self.assertTrue(flags["path_traversal_detected"])

    def test_path_traversal_get_parameter_values_detected(self) -> None:
        source = (
            'String[] values = request.getParameterValues("x");'
            'String param = values[0];'
            'String fileName = base + param;'
            "new java.io.FileInputStream(new java.io.File(fileName));"
        )
        flags = analyze_crypto_indicators(source)
        self.assertTrue(flags["path_traversal_detected"])

    def test_path_traversal_get_the_parameter_detected(self) -> None:
        source = (
            'org.owasp.benchmark.helpers.SeparateClassRequest scr = new org.owasp.benchmark.helpers.SeparateClassRequest(request);'
            'String param = scr.getTheParameter("x");'
            'String bar = param;'
            'new java.io.File(bar, "/Test.txt");'
        )
        flags = analyze_crypto_indicators(source)
        self.assertTrue(flags["path_traversal_detected"])

    def test_path_traversal_safe_constant_not_flagged(self) -> None:
        source = (
            'String param = request.getHeader("x");'
            'String bar = "alsosafe";'
            'String fileName = base + bar;'
            "new java.io.FileOutputStream(fileName);"
        )
        flags = analyze_crypto_indicators(source)
        self.assertFalse(flags["path_traversal_detected"])

    def test_path_traversal_constant_ternary_not_flagged(self) -> None:
        source = (
            'String param = request.getHeader("x");'
            "int num = 106;"
            'String bar = (7 * 18) + num > 200 ? "This_should_always_happen" : param;'
            'String fileName = base + bar;'
            "new java.io.FileInputStream(new java.io.File(fileName));"
        )
        flags = analyze_crypto_indicators(source)
        self.assertFalse(flags["path_traversal_detected"])

    def test_path_traversal_constant_switch_not_flagged(self) -> None:
        source = (
            'String param = request.getHeader("x");'
            'String guess = "ABC";'
            "char switchTarget = guess.charAt(1);"
            "String bar = param;"
            "switch (switchTarget) { case 'A': bar = param; break; case 'B': bar = \"bob\"; break; default: bar = param; break; }"
            'String fileName = base + bar;'
            "new java.io.FileInputStream(fileName);"
        )
        flags = analyze_crypto_indicators(source)
        self.assertFalse(flags["path_traversal_detected"])

    def test_path_traversal_constant_if_else_safe_branch_not_flagged(self) -> None:
        source = (
            'String param = request.getHeader("x");'
            "String bar;"
            "int num = 86;"
            'if ((7 * 42) - num > 200) bar = "This_should_always_happen"; else bar = param;'
            'String fileName = base + bar;'
            "new java.io.FileInputStream(fileName);"
        )
        flags = analyze_crypto_indicators(source)
        self.assertFalse(flags["path_traversal_detected"])

    def test_path_traversal_constant_if_else_tainted_branch_detected(self) -> None:
        source = (
            'String param = request.getHeader("x");'
            "String bar;"
            "int num = 196;"
            'if ((500 / 42) + num > 200) bar = param; else bar = "This should never happen";'
            'String fileName = base + bar;'
            "new java.io.FileInputStream(fileName);"
        )
        flags = analyze_crypto_indicators(source)
        self.assertTrue(flags["path_traversal_detected"])

    def test_classpath_file_read_not_flagged_as_path_traversal(self) -> None:
        source = (
            'String param = request.getCookies()[0].getValue();'
            'new java.io.FileInputStream(org.owasp.benchmark.helpers.Utils.getFileFromClasspath("employees.xml", this.getClass().getClassLoader()));'
            'String expression = "/Employees/Employee[@emplid=\'" + param + "\']";'
        )
        flags = analyze_crypto_indicators(source)
        self.assertFalse(flags["path_traversal_detected"])

    def test_command_injection_detected(self) -> None:
        source = 'String cmd = "echo " + request.getHeader("x"); new ProcessBuilder().command(cmd);'
        flags = analyze_crypto_indicators(source)
        self.assertTrue(flags["command_exec_string_tainted"])
        self.assertFalse(flags["command_exec_args_tainted"])
        self.assertFalse(flags["command_env_only_tainted"])
        self.assertTrue(flags["command_injection_detected"])

    def test_command_injection_builder_detected(self) -> None:
        source = (
            'StringBuilder cmd = new StringBuilder("echo ");'
            'cmd.append(request.getHeader("x"));'
            'Runtime.getRuntime().exec(cmd.toString());'
        )
        flags = analyze_crypto_indicators(source)
        self.assertTrue(flags["command_exec_string_tainted"])
        self.assertTrue(flags["command_injection_detected"])

    def test_command_injection_exec_args_detected(self) -> None:
        source = (
            'String input = request.getHeader("x");'
            'String[] args = new String[] {"sh", "-c", "ls " + input};'
            "Runtime.getRuntime().exec(args);"
        )
        flags = analyze_crypto_indicators(source)
        self.assertFalse(flags["command_exec_string_tainted"])
        self.assertTrue(flags["command_exec_args_tainted"])
        self.assertTrue(flags["command_injection_detected"])

    def test_command_injection_process_builder_list_detected(self) -> None:
        source = (
            'java.util.Enumeration<String> headers = request.getHeaders("x");'
            'String param = headers.nextElement();'
            "java.util.List<String> argList = new java.util.ArrayList<String>();"
            'argList.add("sh");'
            'argList.add("-c");'
            'argList.add("echo " + param);'
            "ProcessBuilder pb = new ProcessBuilder();"
            "pb.command(argList);"
        )
        flags = analyze_crypto_indicators(source)
        self.assertTrue(flags["command_exec_args_tainted"])
        self.assertTrue(flags["command_injection_detected"])

    def test_command_injection_runtime_exec_args_with_get_the_parameter_detected(self) -> None:
        source = (
            'org.owasp.benchmark.helpers.SeparateClassRequest scr = new org.owasp.benchmark.helpers.SeparateClassRequest(request);'
            'String param = scr.getTheParameter("x");'
            'String[] args = new String[] {"sh", "-c", "ls " + param};'
            'String[] argsEnv = {"foo=bar"};'
            "Runtime.getRuntime().exec(args, argsEnv);"
        )
        flags = analyze_crypto_indicators(source)
        self.assertTrue(flags["command_exec_args_tainted"])
        self.assertFalse(flags["command_env_only_tainted"])
        self.assertTrue(flags["command_injection_detected"])

    def test_command_injection_base64_roundtrip_detected(self) -> None:
        source = (
            'String[] values = request.getParameterValues("x");'
            "String param = values[0];"
            'String bar = new String(org.apache.commons.codec.binary.Base64.decodeBase64(org.apache.commons.codec.binary.Base64.encodeBase64(param.getBytes())));'
            'String cmd = "echo " + bar;'
            "Runtime.getRuntime().exec(cmd);"
        )
        flags = analyze_crypto_indicators(source)
        self.assertTrue(flags["command_exec_string_tainted"])
        self.assertTrue(flags["command_injection_detected"])

    def test_command_env_only_taint_not_detected(self) -> None:
        source = (
            'String param = request.getParameter("x");'
            'String cmd = "ls";'
            'String[] argsEnv = {param};'
            "Runtime.getRuntime().exec(cmd, argsEnv);"
        )
        flags = analyze_crypto_indicators(source)
        self.assertFalse(flags["command_exec_string_tainted"])
        self.assertFalse(flags["command_exec_args_tainted"])
        self.assertTrue(flags["command_env_only_tainted"])
        self.assertFalse(flags["command_injection_detected"])

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
        flags = analyze_crypto_indicators(source)
        self.assertFalse(flags["command_exec_string_tainted"])
        self.assertFalse(flags["command_exec_args_tainted"])
        self.assertFalse(flags["command_injection_detected"])

    def test_command_safe_branch_not_poisoned_by_comments_or_annotations(self) -> None:
        source = (
            "/** comment with href = request.getHeader(\\\"x\\\") */"
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
        flags = analyze_crypto_indicators(source)
        self.assertFalse(flags["command_exec_string_tainted"])
        self.assertFalse(flags["command_exec_args_tainted"])
        self.assertFalse(flags["command_injection_detected"])

    def test_ldap_injection_detected(self) -> None:
        source = 'String filter = "(&(uid=" + request.getHeader("x") + "))"; InitialDirContext idc = null; idc.search(base, filter, filters, sc);'
        flags = analyze_crypto_indicators(source)
        self.assertTrue(flags["ldap_injection_detected"])

    def test_ldap_injection_get_headers_detected(self) -> None:
        source = (
            'java.util.Enumeration<String> headers = request.getHeaders("x");'
            'String param = headers.nextElement();'
            'String filter = "(&(uid=" + param + "))";'
            "InitialDirContext idc = null; idc.search(base, filter, filters, sc);"
        )
        flags = analyze_crypto_indicators(source)
        self.assertTrue(flags["ldap_injection_detected"])

    def test_ldap_injection_get_parameter_values_detected(self) -> None:
        source = (
            'String[] values = request.getParameterValues("x");'
            'String bar = values[0];'
            'String filter = "(&(uid=" + bar + "))";'
            "InitialDirContext idc = null; idc.search(base, filter, sc);"
        )
        flags = analyze_crypto_indicators(source)
        self.assertTrue(flags["ldap_injection_detected"])

    def test_xpath_injection_builder_detected(self) -> None:
        source = (
            'StringBuilder expr = new StringBuilder("/Employees/Employee[@emplid=\'");'
            'expr.append(request.getHeader("x"));'
            'expr.append("\']"); XPathFactory.newInstance(); xp.evaluate(expr.toString(), xmlDocument);'
        )
        flags = analyze_crypto_indicators(source)
        self.assertTrue(flags["xpath_injection_detected"])

    def test_sql_dynamic_query_detected(self) -> None:
        source = (
            'StringBuilder sql = new StringBuilder("select * from users where name = \'");'
            'sql.append(request.getHeader("x"));'
            'sql.append("\'"); connection.prepareCall(sql.toString());'
        )
        flags = analyze_crypto_indicators(source)
        self.assertTrue(flags["sql_dynamic_query_detected"])

    def test_sql_dynamic_query_jdbc_template_detected(self) -> None:
        source = (
            'String[] values = request.getParameterMap().get("x");'
            'String sql = "select * from users where name = \'" + values[0] + "\'";'
            "org.owasp.benchmark.helpers.DatabaseHelper.JDBCtemplate.queryForRowSet(sql);"
        )
        flags = analyze_crypto_indicators(source)
        self.assertTrue(flags["sql_dynamic_query_detected"])

    def test_sql_dynamic_query_prepare_statement_detected(self) -> None:
        source = (
            'String[] values = request.getParameterValues("x");'
            'String sql = "select * from users where username=? and password=\'" + values[0] + "\'";'
            "connection.prepareStatement(sql);"
        )
        flags = analyze_crypto_indicators(source)
        self.assertTrue(flags["sql_dynamic_query_detected"])

    def test_xpath_injection_detected(self) -> None:
        source = 'String expr = "/Employees/Employee[@emplid=\'" + request.getHeader("x") + "\']"; XPathFactory.newInstance(); xp.evaluate(expr, xmlDocument);'
        flags = analyze_crypto_indicators(source)
        self.assertTrue(flags["xpath_injection_detected"])

    def test_sql_prepare_call_flags(self) -> None:
        source = 'java.sql.CallableStatement statement = connection.prepareCall(sql);'
        flags = analyze_crypto_indicators(source)
        self.assertTrue(flags["sql_prepare_call_detected"])
        self.assertTrue(flags["sql_callable_statement_detected"])


if __name__ == "__main__":
    unittest.main()
