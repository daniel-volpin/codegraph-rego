import unittest

from codegraph.policy.source_analysis import analyze_crypto_indicators


class TestPathTraversalDetected(unittest.TestCase):
    def test_path_traversal_detected(self) -> None:
        source = 'String fileName = base + request.getHeader("x"); new java.io.FileInputStream(new java.io.File(fileName));'
        flags = analyze_crypto_indicators(source)
        self.assertTrue(flags["path_traversal_detected"])
        self.assertTrue(flags["path_sink_uses_tainted_input"])
        self.assertFalse(flags["path_sink_uses_safe_resource_helper"])

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

    def test_path_traversal_nested_parent_child_file_detected(self) -> None:
        source = (
            'String[] values = request.getParameterValues("x");'
            'String bar = values[0];'
            'new java.io.File(new java.io.File(org.owasp.benchmark.helpers.Utils.TESTFILES_DIR), bar);'
        )
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

    def test_path_traversal_cookie_base64_flow_uses_compatibility_signal(self) -> None:
        source = (
            "javax.servlet.http.Cookie[] theCookies = request.getCookies();"
            'String param = "noCookieValueSupplied";'
            'param = java.net.URLDecoder.decode(theCookies[0].getValue(), "UTF-8");'
            "String bar = new String(org.apache.commons.codec.binary.Base64.decodeBase64("
            "org.apache.commons.codec.binary.Base64.encodeBase64(param.getBytes())));"
            'new java.io.File(bar, "/Test.txt");'
        )
        flags = analyze_crypto_indicators(source)
        self.assertTrue(flags["path_traversal_detected"])
        self.assertFalse(flags["path_sink_uses_safe_constant"])
        self.assertFalse(flags["path_sink_uses_safe_resource_helper"])

    def test_path_traversal_helper_collection_flow_uses_compatibility_signal(self) -> None:
        source = (
            "java.util.Map<String, String[]> map = request.getParameterMap();"
            'String[] values = map.get("BenchmarkTest01329");'
            'String param = values[0];'
            "java.util.List<String> valuesList = new java.util.ArrayList<String>();"
            'valuesList.add("safe");'
            "valuesList.add(param);"
            'valuesList.add("moresafe");'
            "valuesList.remove(0);"
            "String bar = valuesList.get(0);"
            'String fileURI = base + bar;'
            "new java.io.File(fileURI);"
        )
        flags = analyze_crypto_indicators(source)
        self.assertTrue(flags["path_traversal_detected"])
        self.assertFalse(flags["path_sink_uses_safe_constant"])

    def test_path_local_collection_tainted_selection_detected(self) -> None:
        source = (
            'String param = request.getHeader("x");'
            'String bar = "alsosafe";'
            "java.util.List<String> valuesList = new java.util.ArrayList<String>();"
            'valuesList.add("safe");'
            "valuesList.add(param);"
            'valuesList.add("moresafe");'
            "valuesList.remove(0);"
            "bar = valuesList.get(0);"
            'String fileName = base + bar;'
            "new java.io.FileInputStream(fileName);"
        )
        flags = analyze_crypto_indicators(source)
        self.assertTrue(flags["path_traversal_detected"])
        self.assertTrue(flags["path_sink_uses_tainted_input"])


class TestPathTraversalNotFlagged(unittest.TestCase):
    def test_path_traversal_safe_constant_not_flagged(self) -> None:
        source = (
            'String param = request.getHeader("x");'
            'String bar = "alsosafe";'
            'String fileName = base + bar;'
            "new java.io.FileOutputStream(fileName);"
        )
        flags = analyze_crypto_indicators(source)
        self.assertFalse(flags["path_traversal_detected"])
        self.assertTrue(flags["path_sink_uses_safe_constant"])

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

    def test_classpath_file_read_not_flagged_as_path_traversal(self) -> None:
        source = (
            'String param = request.getCookies()[0].getValue();'
            'new java.io.FileInputStream(org.owasp.benchmark.helpers.Utils.getFileFromClasspath("employees.xml", this.getClass().getClassLoader()));'
            'String expression = "/Employees/Employee[@emplid=\'" + param + "\']";'
        )
        flags = analyze_crypto_indicators(source)
        self.assertFalse(flags["path_traversal_detected"])
        self.assertTrue(flags["path_sink_uses_safe_resource_helper"])

    def test_path_fixed_literal_sink_not_suppressed_by_unrelated_param(self) -> None:
        source = (
            'String param = request.getHeader("x");'
            'String bar = "safe.txt";'
            'String fileName = bar;'
            'String other = base + param;'
            "new java.io.FileInputStream(fileName);"
        )
        flags = analyze_crypto_indicators(source)
        self.assertFalse(flags["path_traversal_detected"])
        self.assertTrue(flags["path_sink_uses_safe_constant"])

    def test_path_safe_constant_elsewhere_does_not_suppress_tainted_sink(self) -> None:
        source = (
            'String param = request.getHeader("x");'
            'String safeName = "safe.txt";'
            'String fileName = base + param;'
            "new java.io.FileInputStream(fileName);"
        )
        flags = analyze_crypto_indicators(source)
        self.assertTrue(flags["path_traversal_detected"])
        self.assertTrue(flags["path_sink_uses_tainted_input"])
        self.assertFalse(flags["path_sink_uses_safe_constant"])

    def test_path_local_collection_safe_selection_not_flagged(self) -> None:
        source = (
            'String param = request.getHeader("x");'
            'String bar = "alsosafe";'
            "java.util.List<String> valuesList = new java.util.ArrayList<String>();"
            'valuesList.add("safe");'
            "valuesList.add(param);"
            'valuesList.add("moresafe");'
            "valuesList.remove(0);"
            "bar = valuesList.get(1);"
            'String fileName = base + bar;'
            "new java.io.FileInputStream(fileName);"
        )
        flags = analyze_crypto_indicators(source)
        self.assertFalse(flags["path_traversal_detected"])
        self.assertTrue(flags["path_sink_uses_safe_constant"])


if __name__ == "__main__":
    unittest.main()
