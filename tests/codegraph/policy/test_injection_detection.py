import unittest

from tests.codegraph.policy._test_helpers import PolicyTestBase, BundleBuilder


class TestPathTraversalDetection(PolicyTestBase):
    """Tests for path traversal injection detection."""

    def test_evaluate_bundle_respects_clean_path_flag_over_source_fallback(self) -> None:
        from codegraph.policy.integration import evaluate_bundle

        bundle = (
            BundleBuilder()
            .with_target_method(
                "org.owasp.benchmark.testcode.BenchmarkTest99995.doPost(HttpServletRequest,HttpServletResponse)"
            )
            .with_file_path("src/main/java/org/owasp/benchmark/testcode/BenchmarkTest99995.java")
            .with_source_code(
                'String param = request.getHeader("x");'
                'String bar = "alsosafe";'
                "String fileName = base + bar;"
                "new java.io.FileOutputStream(fileName);"
            )
            .with_annotation("WebServlet")
            .with_analysis_flags(
                {
                    "md5_detected": False,
                    "weak_cipher_detected": False,
                    "insecure_random_detected": False,
                    "sha1prng_detected": False,
                    "path_traversal_detected": False,
                    "path_safe_constant_detected": True,
                    "path_sink_uses_tainted_input": False,
                    "path_sink_uses_safe_constant": True,
                    "path_sink_uses_safe_resource_helper": False,
                    "command_injection_detected": False,
                    "ldap_injection_detected": False,
                    "xpath_injection_detected": False,
                    "sql_prepare_call_detected": False,
                    "sql_callable_statement_detected": False,
                }
            )
            .build()
        )

        violations = evaluate_bundle(bundle)
        violation_ids = self._normalized_violation_ids(violations)
        self.assertNotIn("ISO-A.8-PATH-TRAVERSAL", violation_ids)

    def test_evaluate_bundle_suppresses_safe_helper_direct_path_sink(self) -> None:
        from codegraph.policy.integration import evaluate_bundle

        bundle = (
            BundleBuilder()
            .with_target_method(
                "org.owasp.benchmark.testcode.BenchmarkTest99991.doPost(HttpServletRequest,HttpServletResponse)"
            )
            .with_file_path("src/main/java/org/owasp/benchmark/testcode/BenchmarkTest99991.java")
            .with_source_code(
                'String param = request.getHeader("x");String bar = doSomething(param);new java.io.File(bar);'
            )
            .with_annotation("WebServlet")
            .with_analysis_flags(
                {
                    "md5_detected": False,
                    "weak_cipher_detected": False,
                    "insecure_random_detected": False,
                    "sha1prng_detected": False,
                    "path_traversal_detected": True,
                    "path_safe_constant_detected": False,
                    "path_sink_uses_tainted_input": True,
                    "path_sink_uses_safe_constant": False,
                    "path_sink_uses_safe_resource_helper": False,
                    "command_injection_detected": False,
                    "ldap_injection_detected": False,
                    "xpath_injection_detected": False,
                    "sql_prepare_call_detected": False,
                    "sql_callable_statement_detected": False,
                }
            )
            .with_helper_summaries(
                {
                    "safe_constant_return_vars": ["bar"],
                    "tainted_return_vars": [],
                    "safe_constant_return_used_in_path_sink": True,
                    "safe_constant_return_used_in_ldap_filter": False,
                    "safe_constant_return_used_in_command_sink": False,
                }
            )
            .build()
        )

        violations = evaluate_bundle(bundle)
        violation_ids = self._normalized_violation_ids(violations)
        self.assertNotIn("ISO-A.8-PATH-TRAVERSAL", violation_ids)

    def test_evaluate_bundle_flags_tainted_helper_path_sink(self) -> None:
        from codegraph.policy.integration import evaluate_bundle

        bundle = (
            BundleBuilder()
            .with_target_method(
                "org.owasp.benchmark.testcode.BenchmarkTest99988.doPost(HttpServletRequest,HttpServletResponse)"
            )
            .with_file_path("src/main/java/org/owasp/benchmark/testcode/BenchmarkTest99988.java")
            .with_source_code(
                'String[] values = request.getParameterValues("x");'
                "String param = values[0];"
                "String bar = doSomething(param);"
                "new java.io.File(new java.io.File(org.owasp.benchmark.helpers.Utils.TESTFILES_DIR), bar);"
            )
            .with_annotation("WebServlet")
            .with_analysis_flags(
                {
                    "md5_detected": False,
                    "weak_cipher_detected": False,
                    "insecure_random_detected": False,
                    "sha1prng_detected": False,
                    "path_traversal_detected": False,
                    "path_safe_constant_detected": False,
                    "path_sink_uses_tainted_input": False,
                    "path_sink_uses_safe_constant": False,
                    "path_sink_uses_safe_resource_helper": False,
                    "command_injection_detected": False,
                    "ldap_injection_detected": False,
                    "xpath_injection_detected": False,
                    "sql_prepare_call_detected": False,
                    "sql_callable_statement_detected": False,
                }
            )
            .with_helper_summaries(
                {
                    "safe_constant_return_vars": [],
                    "tainted_return_vars": ["bar"],
                    "safe_constant_return_used_in_path_sink": False,
                    "tainted_return_used_in_path_sink": True,
                    "safe_constant_return_used_in_ldap_filter": False,
                    "safe_constant_return_used_in_command_sink": False,
                }
            )
            .build()
        )

        violations = evaluate_bundle(bundle)
        violation_ids = self._normalized_violation_ids(violations)
        self.assertIn("ISO-A.8-PATH-TRAVERSAL", violation_ids)

    def test_evaluate_bundle_respects_safe_resource_path_flag(self) -> None:
        from codegraph.policy.integration import evaluate_bundle

        bundle = (
            BundleBuilder()
            .with_target_method(
                "org.owasp.benchmark.testcode.BenchmarkTest99990.doPost(HttpServletRequest,HttpServletResponse)"
            )
            .with_file_path("src/main/java/org/owasp/benchmark/testcode/BenchmarkTest99990.java")
            .with_source_code(
                'String param = request.getHeader("x");'
                'new java.io.FileInputStream(org.owasp.benchmark.helpers.Utils.getFileFromClasspath("employees.xml", this.getClass().getClassLoader()));'
            )
            .with_annotation("WebServlet")
            .with_analysis_flags(
                {
                    "md5_detected": False,
                    "weak_cipher_detected": False,
                    "insecure_random_detected": False,
                    "sha1prng_detected": False,
                    "path_traversal_detected": False,
                    "path_safe_constant_detected": False,
                    "path_sink_uses_tainted_input": False,
                    "path_sink_uses_safe_constant": False,
                    "path_sink_uses_safe_resource_helper": True,
                    "command_injection_detected": False,
                    "ldap_injection_detected": False,
                    "xpath_injection_detected": False,
                    "sql_prepare_call_detected": False,
                    "sql_callable_statement_detected": False,
                }
            )
            .build()
        )

        violations = evaluate_bundle(bundle)
        violation_ids = self._normalized_violation_ids(violations)
        self.assertNotIn("ISO-A.8-PATH-TRAVERSAL", violation_ids)

    def test_evaluate_bundle_does_not_retrigger_path_source_fallback_when_flags_present(self) -> None:
        from codegraph.policy.integration import evaluate_bundle

        bundle = (
            BundleBuilder()
            .with_target_method(
                "org.owasp.benchmark.testcode.BenchmarkTest99989.doPost(HttpServletRequest,HttpServletResponse)"
            )
            .with_file_path("src/main/java/org/owasp/benchmark/testcode/BenchmarkTest99989.java")
            .with_source_code(
                'String param = request.getHeader("x");'
                'String bar = "alsosafe";'
                "String fileName = base + bar;"
                "new java.io.FileOutputStream(fileName);"
            )
            .with_annotation("WebServlet")
            .with_analysis_flags(
                {
                    "md5_detected": False,
                    "weak_cipher_detected": False,
                    "insecure_random_detected": False,
                    "sha1prng_detected": False,
                    "path_traversal_detected": False,
                    "path_safe_constant_detected": True,
                    "path_sink_uses_tainted_input": False,
                    "path_sink_uses_safe_constant": True,
                    "path_sink_uses_safe_resource_helper": False,
                    "command_injection_detected": False,
                    "ldap_injection_detected": False,
                    "xpath_injection_detected": False,
                    "sql_prepare_call_detected": False,
                    "sql_callable_statement_detected": False,
                }
            )
            .build()
        )

        violations = evaluate_bundle(bundle)
        violation_ids = self._normalized_violation_ids(violations)
        self.assertNotIn("ISO-A.8-PATH-TRAVERSAL", violation_ids)

    def test_evaluate_bundle_can_fallback_to_source_for_path_traversal_when_flags_missing(self) -> None:
        from codegraph.policy.integration import evaluate_bundle

        bundle = {
            "target_method": "org.owasp.benchmark.testcode.BenchmarkTest99994.doPost(HttpServletRequest,HttpServletResponse)",
            "file_path": "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest99994.java",
            "source_code": (
                'String param = request.getHeader("x");'
                "String fileName = base + param;"
                "new java.io.FileInputStream(fileName);"
            ),
            "graph_context": {"annotations": ["WebServlet"], "uses_fields": [], "calls": [], "callers": []},
            "analysis_flags": None,
        }

        violations = evaluate_bundle(bundle)
        violation_ids = self._normalized_violation_ids(violations)
        self.assertIn("ISO-A.8-PATH-TRAVERSAL", violation_ids)


class TestCommandInjectionDetection(PolicyTestBase):
    """Tests for command injection detection."""

    def test_evaluate_bundle_flags_command_payload_taint(self) -> None:
        from codegraph.policy.integration import evaluate_bundle

        bundle = (
            BundleBuilder()
            .with_target_method(
                "org.owasp.benchmark.testcode.BenchmarkTest99990.doPost(HttpServletRequest,HttpServletResponse)"
            )
            .with_file_path("src/main/java/org/owasp/benchmark/testcode/BenchmarkTest99990.java")
            .with_source_code(
                'String param = request.getHeader("x");String cmd = "echo " + param;Runtime.getRuntime().exec(cmd);'
            )
            .with_annotation("WebServlet")
            .with_analysis_flags(
                {
                    "md5_detected": False,
                    "weak_cipher_detected": False,
                    "insecure_random_detected": False,
                    "sha1prng_detected": False,
                    "path_traversal_detected": False,
                    "path_safe_constant_detected": False,
                    "command_exec_string_tainted": True,
                    "command_exec_args_tainted": False,
                    "command_env_only_tainted": False,
                    "command_injection_detected": True,
                    "ldap_injection_detected": False,
                    "xpath_injection_detected": False,
                    "sql_prepare_call_detected": False,
                    "sql_callable_statement_detected": False,
                }
            )
            .build()
        )

        violations = evaluate_bundle(bundle)
        violation_ids = self._normalized_violation_ids(violations)
        self.assertIn("ISO-A.8-CMD-INJECTION", violation_ids)

    def test_evaluate_bundle_flags_command_env_only_taint(self) -> None:
        from codegraph.policy.integration import evaluate_bundle

        bundle = (
            BundleBuilder()
            .with_target_method(
                "org.owasp.benchmark.testcode.BenchmarkTest99989.doPost(HttpServletRequest,HttpServletResponse)"
            )
            .with_file_path("src/main/java/org/owasp/benchmark/testcode/BenchmarkTest99989.java")
            .with_source_code(
                'String param = request.getHeader("x");'
                'String cmd = "ls";'
                "String[] argsEnv = {param};"
                "Runtime.getRuntime().exec(cmd, argsEnv);"
            )
            .with_annotation("WebServlet")
            .with_analysis_flags(
                {
                    "md5_detected": False,
                    "weak_cipher_detected": False,
                    "insecure_random_detected": False,
                    "sha1prng_detected": False,
                    "path_traversal_detected": False,
                    "path_safe_constant_detected": False,
                    "command_exec_string_tainted": False,
                    "command_exec_args_tainted": False,
                    "command_env_only_tainted": True,
                    "command_injection_detected": False,
                    "ldap_injection_detected": False,
                    "xpath_injection_detected": False,
                    "sql_prepare_call_detected": False,
                    "sql_callable_statement_detected": False,
                }
            )
            .with_helper_summaries(
                {
                    "safe_constant_return_vars": [],
                    "tainted_return_vars": [],
                    "safe_constant_return_used_in_path_sink": False,
                    "safe_constant_return_used_in_ldap_filter": False,
                    "safe_constant_return_used_in_command_sink": False,
                    "tainted_return_used_in_command_sink": False,
                }
            )
            .build()
        )

        violations = evaluate_bundle(bundle)
        violation_ids = self._normalized_violation_ids(violations)
        self.assertIn("ISO-A.8-CMD-INJECTION", violation_ids)

    def test_evaluate_bundle_flags_tainted_helper_command_payload(self) -> None:
        from codegraph.policy.integration import evaluate_bundle

        bundle = (
            BundleBuilder()
            .with_target_method(
                "org.owasp.benchmark.testcode.BenchmarkTest99988.doPost(HttpServletRequest,HttpServletResponse)"
            )
            .with_file_path("src/main/java/org/owasp/benchmark/testcode/BenchmarkTest99988.java")
            .with_source_code(
                'String param = request.getHeader("x");'
                "String bar = doSomething(param);"
                'String[] args = new String[] {"sh", "-c", "ls " + bar};'
                "Runtime.getRuntime().exec(args);"
            )
            .with_annotation("WebServlet")
            .with_analysis_flags(
                {
                    "md5_detected": False,
                    "weak_cipher_detected": False,
                    "insecure_random_detected": False,
                    "sha1prng_detected": False,
                    "path_traversal_detected": False,
                    "path_safe_constant_detected": False,
                    "command_exec_string_tainted": False,
                    "command_exec_args_tainted": False,
                    "command_env_only_tainted": False,
                    "command_injection_detected": False,
                    "ldap_injection_detected": False,
                    "xpath_injection_detected": False,
                    "sql_prepare_call_detected": False,
                    "sql_callable_statement_detected": False,
                }
            )
            .with_helper_summaries(
                {
                    "safe_constant_return_vars": [],
                    "tainted_return_vars": ["bar"],
                    "safe_constant_return_used_in_path_sink": False,
                    "safe_constant_return_used_in_ldap_filter": False,
                    "safe_constant_return_used_in_command_sink": False,
                    "tainted_return_used_in_command_sink": True,
                }
            )
            .build()
        )

        violations = evaluate_bundle(bundle)
        violation_ids = self._normalized_violation_ids(violations)
        self.assertIn("ISO-A.8-CMD-INJECTION", violation_ids)

    def test_evaluate_bundle_flags_tainted_helper_command_env_payload(self) -> None:
        from codegraph.policy.integration import evaluate_bundle

        bundle = (
            BundleBuilder()
            .with_target_method(
                "org.owasp.benchmark.testcode.BenchmarkTest99988.doPost(HttpServletRequest,HttpServletResponse)"
            )
            .with_file_path("src/main/java/org/owasp/benchmark/testcode/BenchmarkTest99988.java")
            .with_source_code(
                'String param = request.getHeader("x");'
                "String bar = doSomething(param);"
                'String cmd = "ls";'
                "String[] argsEnv = {bar};"
                "Runtime.getRuntime().exec(cmd, argsEnv);"
            )
            .with_annotation("WebServlet")
            .with_analysis_flags(
                {
                    "md5_detected": False,
                    "weak_cipher_detected": False,
                    "insecure_random_detected": False,
                    "sha1prng_detected": False,
                    "path_traversal_detected": False,
                    "path_safe_constant_detected": False,
                    "command_exec_string_tainted": False,
                    "command_exec_args_tainted": False,
                    "command_env_only_tainted": False,
                    "command_injection_detected": False,
                    "ldap_injection_detected": False,
                    "xpath_injection_detected": False,
                    "sql_prepare_call_detected": False,
                    "sql_callable_statement_detected": False,
                }
            )
            .with_helper_summaries(
                {
                    "safe_constant_return_vars": [],
                    "tainted_return_vars": ["bar"],
                    "safe_constant_return_used_in_path_sink": False,
                    "safe_constant_return_used_in_ldap_filter": False,
                    "safe_constant_return_used_in_command_sink": False,
                    "tainted_return_used_in_command_sink": True,
                }
            )
            .build()
        )

        violations = evaluate_bundle(bundle)
        violation_ids = self._normalized_violation_ids(violations)
        self.assertIn("ISO-A.8-CMD-INJECTION", violation_ids)

    def test_evaluate_bundle_suppresses_safe_helper_command_payload(self) -> None:
        from codegraph.policy.integration import evaluate_bundle

        bundle = (
            BundleBuilder()
            .with_target_method(
                "org.owasp.benchmark.testcode.BenchmarkTest99987.doPost(HttpServletRequest,HttpServletResponse)"
            )
            .with_file_path("src/main/java/org/owasp/benchmark/testcode/BenchmarkTest99987.java")
            .with_source_code(
                'String param = request.getHeader("x");'
                "String bar = doSomething(param);"
                'String[] args = new String[] {"sh", "-c", "ls " + bar};'
                "ProcessBuilder pb = new ProcessBuilder();"
                "pb.command(args);"
            )
            .with_annotation("WebServlet")
            .with_analysis_flags(
                {
                    "md5_detected": False,
                    "weak_cipher_detected": False,
                    "insecure_random_detected": False,
                    "sha1prng_detected": False,
                    "path_traversal_detected": False,
                    "path_safe_constant_detected": False,
                    "command_exec_string_tainted": False,
                    "command_exec_args_tainted": True,
                    "command_env_only_tainted": False,
                    "command_injection_detected": True,
                    "ldap_injection_detected": False,
                    "xpath_injection_detected": False,
                    "sql_prepare_call_detected": False,
                    "sql_callable_statement_detected": False,
                }
            )
            .with_helper_summaries(
                {
                    "safe_constant_return_vars": ["bar"],
                    "tainted_return_vars": [],
                    "safe_constant_return_used_in_path_sink": False,
                    "safe_constant_return_used_in_ldap_filter": False,
                    "safe_constant_return_used_in_command_sink": True,
                    "tainted_return_used_in_command_sink": False,
                }
            )
            .build()
        )

        violations = evaluate_bundle(bundle)
        violation_ids = self._normalized_violation_ids(violations)
        self.assertNotIn("ISO-A.8-CMD-INJECTION", violation_ids)


class TestLDAPInjectionDetection(PolicyTestBase):
    """Tests for LDAP injection detection."""

    def test_evaluate_bundle_suppresses_safe_helper_ldap_filter(self) -> None:
        from codegraph.policy.integration import evaluate_bundle

        bundle = (
            BundleBuilder()
            .with_target_method(
                "org.owasp.benchmark.testcode.BenchmarkTest99993.doPost(HttpServletRequest,HttpServletResponse)"
            )
            .with_file_path("src/main/java/org/owasp/benchmark/testcode/BenchmarkTest99993.java")
            .with_source_code(
                'String param = request.getHeader("x");'
                "String bar = doSomething(param);"
                'String filter = "(&(uid=" + bar + "))";'
                "InitialDirContext idc = null; idc.search(base, filter, filters, sc);"
            )
            .with_annotation("WebServlet")
            .with_analysis_flags(
                {
                    "md5_detected": False,
                    "weak_cipher_detected": False,
                    "insecure_random_detected": False,
                    "sha1prng_detected": False,
                    "path_traversal_detected": False,
                    "path_safe_constant_detected": False,
                    "command_injection_detected": False,
                    "ldap_injection_detected": True,
                    "xpath_injection_detected": False,
                    "sql_prepare_call_detected": False,
                    "sql_callable_statement_detected": False,
                }
            )
            .with_helper_summaries(
                {
                    "safe_constant_return_vars": ["bar"],
                    "tainted_return_vars": [],
                    "safe_constant_return_used_in_path_sink": False,
                    "safe_constant_return_used_in_ldap_filter": True,
                    "safe_constant_return_used_in_command_sink": False,
                }
            )
            .build()
        )

        violations = evaluate_bundle(bundle)
        violation_ids = self._normalized_violation_ids(violations)
        self.assertNotIn("ISO-A.8-LDAP-INJECTION", violation_ids)

    def test_evaluate_bundle_does_not_suppress_tainted_helper_ldap_filter(self) -> None:
        from codegraph.policy.integration import evaluate_bundle

        bundle = (
            BundleBuilder()
            .with_target_method(
                "org.owasp.benchmark.testcode.BenchmarkTest99992.doPost(HttpServletRequest,HttpServletResponse)"
            )
            .with_file_path("src/main/java/org/owasp/benchmark/testcode/BenchmarkTest99992.java")
            .with_source_code(
                'String param = request.getHeader("x");'
                "String bar = doSomething(param);"
                'String filter = "(&(uid=" + bar + "))";'
                "InitialDirContext idc = null; idc.search(base, filter, filters, sc);"
            )
            .with_annotation("WebServlet")
            .with_analysis_flags(
                {
                    "md5_detected": False,
                    "weak_cipher_detected": False,
                    "insecure_random_detected": False,
                    "sha1prng_detected": False,
                    "path_traversal_detected": False,
                    "path_safe_constant_detected": False,
                    "command_injection_detected": False,
                    "ldap_injection_detected": True,
                    "xpath_injection_detected": False,
                    "sql_prepare_call_detected": False,
                    "sql_callable_statement_detected": False,
                }
            )
            .with_helper_summaries(
                {
                    "safe_constant_return_vars": [],
                    "tainted_return_vars": ["bar"],
                    "safe_constant_return_used_in_path_sink": False,
                    "safe_constant_return_used_in_ldap_filter": False,
                    "tainted_return_used_in_ldap_filter": True,
                    "safe_constant_return_used_in_command_sink": False,
                }
            )
            .build()
        )

        violations = evaluate_bundle(bundle)
        violation_ids = self._normalized_violation_ids(violations)
        self.assertIn("ISO-A.8-LDAP-INJECTION", violation_ids)

    def test_evaluate_bundle_respects_clean_ldap_flag_over_source_fallback(self) -> None:
        from codegraph.policy.integration import evaluate_bundle

        bundle = (
            BundleBuilder()
            .with_target_method(
                "org.owasp.benchmark.testcode.BenchmarkTest99990.doPost(HttpServletRequest,HttpServletResponse)"
            )
            .with_file_path("src/main/java/org/owasp/benchmark/testcode/BenchmarkTest99990.java")
            .with_source_code(
                'String param = request.getHeader("x");'
                'String bar = "safe";'
                'String filter = "(&(uid=" + bar + "))";'
                "InitialDirContext idc = null; idc.search(base, filter, filters, sc);"
            )
            .with_annotation("WebServlet")
            .with_analysis_flags(
                {
                    "md5_detected": False,
                    "weak_cipher_detected": False,
                    "insecure_random_detected": False,
                    "sha1prng_detected": False,
                    "path_traversal_detected": False,
                    "path_safe_constant_detected": False,
                    "command_injection_detected": False,
                    "ldap_injection_detected": False,
                    "ldap_filter_uses_tainted_input": False,
                    "ldap_filter_uses_safe_constant": True,
                    "xpath_injection_detected": False,
                    "sql_prepare_call_detected": False,
                    "sql_callable_statement_detected": False,
                }
            )
            .with_helper_summaries(
                {
                    "safe_constant_return_vars": [],
                    "tainted_return_vars": [],
                    "safe_constant_return_used_in_path_sink": False,
                    "safe_constant_return_used_in_ldap_filter": False,
                    "tainted_return_used_in_ldap_filter": False,
                    "safe_constant_return_used_in_command_sink": False,
                }
            )
            .build()
        )

        violations = evaluate_bundle(bundle)
        violation_ids = self._normalized_violation_ids(violations)
        self.assertNotIn("ISO-A.8-LDAP-INJECTION", violation_ids)

    def test_evaluate_bundle_suppresses_safe_constant_argument_helper_ldap_filter(self) -> None:
        from codegraph.policy.integration import evaluate_bundle

        bundle = (
            BundleBuilder()
            .with_target_method(
                "org.owasp.benchmark.testcode.BenchmarkTest99989.doPost(HttpServletRequest,HttpServletResponse)"
            )
            .with_file_path("src/main/java/org/owasp/benchmark/testcode/BenchmarkTest99989.java")
            .with_source_code(
                'String param = request.getParameterValues("x")[0];'
                'String safeInput = "barbarians_at_the_gate";'
                "String bar = thing.doSomething(safeInput);"
                'String filter = "(&(uid=" + bar + "))";'
                "InitialDirContext idc = null; idc.search(base, filter, filters, sc);"
            )
            .with_annotation("WebServlet")
            .with_analysis_flags(
                {
                    "md5_detected": False,
                    "weak_cipher_detected": False,
                    "insecure_random_detected": False,
                    "sha1prng_detected": False,
                    "path_traversal_detected": False,
                    "path_safe_constant_detected": False,
                    "command_injection_detected": False,
                    "ldap_injection_detected": False,
                    "ldap_filter_uses_tainted_input": False,
                    "ldap_filter_uses_safe_constant": False,
                    "xpath_injection_detected": False,
                    "sql_prepare_call_detected": False,
                    "sql_callable_statement_detected": False,
                }
            )
            .with_helper_summaries(
                {
                    "safe_constant_return_vars": ["bar"],
                    "tainted_return_vars": [],
                    "safe_constant_return_used_in_path_sink": False,
                    "safe_constant_return_used_in_ldap_filter": True,
                    "tainted_return_used_in_ldap_filter": False,
                    "safe_constant_return_used_in_command_sink": False,
                }
            )
            .build()
        )

        violations = evaluate_bundle(bundle)
        violation_ids = self._normalized_violation_ids(violations)
        self.assertNotIn("ISO-A.8-LDAP-INJECTION", violation_ids)


class TestXPathInjectionDetection(PolicyTestBase):
    """Tests for XPath injection detection."""

    def test_evaluate_bundle_suppresses_safe_helper_xpath_query(self) -> None:
        from codegraph.policy.integration import evaluate_bundle

        bundle = (
            BundleBuilder()
            .with_target_method(
                "org.owasp.benchmark.testcode.BenchmarkTest99995.doPost(HttpServletRequest,HttpServletResponse)"
            )
            .with_file_path("src/main/java/org/owasp/benchmark/testcode/BenchmarkTest99995.java")
            .with_source_code(
                'String param = request.getHeader("x");'
                "String bar = doSomething(param);"
                'String expression = "/Employees/Employee[@emplid=\'" + bar + "\']";'
                "XPathFactory.newInstance(); xp.evaluate(expression, xmlDocument);"
            )
            .with_annotation("WebServlet")
            .with_analysis_flags(
                {
                    "md5_detected": False,
                    "weak_cipher_detected": False,
                    "insecure_random_detected": False,
                    "sha1prng_detected": False,
                    "path_traversal_detected": False,
                    "path_safe_constant_detected": False,
                    "command_injection_detected": False,
                    "ldap_injection_detected": False,
                    "xpath_injection_detected": True,
                    "xpath_query_uses_tainted_input": False,
                    "xpath_query_uses_safe_constant": False,
                    "sql_prepare_call_detected": False,
                    "sql_callable_statement_detected": False,
                }
            )
            .with_helper_summaries(
                {
                    "safe_constant_return_vars": ["bar"],
                    "tainted_return_vars": [],
                    "safe_constant_return_used_in_path_sink": False,
                    "safe_constant_return_used_in_ldap_filter": False,
                    "safe_constant_return_used_in_xpath_query": True,
                    "safe_constant_return_used_in_command_sink": False,
                    "tainted_return_used_in_xpath_query": False,
                    "tainted_return_used_in_command_sink": False,
                }
            )
            .build()
        )

        violations = evaluate_bundle(bundle)
        violation_ids = self._normalized_violation_ids(violations)
        self.assertNotIn("ISO-A.8-XPATH-INJECTION", violation_ids)

    def test_evaluate_bundle_flags_tainted_helper_xpath_query(self) -> None:
        from codegraph.policy.integration import evaluate_bundle

        bundle = (
            BundleBuilder()
            .with_target_method(
                "org.owasp.benchmark.testcode.BenchmarkTest99996.doPost(HttpServletRequest,HttpServletResponse)"
            )
            .with_file_path("src/main/java/org/owasp/benchmark/testcode/BenchmarkTest99996.java")
            .with_source_code(
                'String param = request.getHeader("x");'
                "String bar = doSomething(param);"
                'String expression = "/Employees/Employee[@emplid=\'" + bar + "\']";'
                "XPathFactory.newInstance(); xp.compile(expression).evaluate(xmlDocument, javax.xml.xpath.XPathConstants.NODESET);"
            )
            .with_annotation("WebServlet")
            .with_analysis_flags(
                {
                    "md5_detected": False,
                    "weak_cipher_detected": False,
                    "insecure_random_detected": False,
                    "sha1prng_detected": False,
                    "path_traversal_detected": False,
                    "path_safe_constant_detected": False,
                    "command_injection_detected": False,
                    "ldap_injection_detected": False,
                    "xpath_injection_detected": False,
                    "xpath_query_uses_tainted_input": False,
                    "xpath_query_uses_safe_constant": False,
                    "sql_prepare_call_detected": False,
                    "sql_callable_statement_detected": False,
                }
            )
            .with_helper_summaries(
                {
                    "safe_constant_return_vars": [],
                    "tainted_return_vars": ["bar"],
                    "safe_constant_return_used_in_path_sink": False,
                    "safe_constant_return_used_in_ldap_filter": False,
                    "safe_constant_return_used_in_xpath_query": False,
                    "safe_constant_return_used_in_command_sink": False,
                    "tainted_return_used_in_xpath_query": True,
                    "tainted_return_used_in_command_sink": False,
                }
            )
            .build()
        )

        violations = evaluate_bundle(bundle)
        violation_ids = self._normalized_violation_ids(violations)
        self.assertIn("ISO-A.8-XPATH-INJECTION", violation_ids)


class TestSQLInjectionDetection(PolicyTestBase):
    """Tests for SQL injection detection."""

    def test_evaluate_bundle_does_not_use_sql_fallback_for_placeholder_prepared_statement(self) -> None:
        from codegraph.policy.integration import evaluate_bundle

        bundle = (
            BundleBuilder()
            .with_target_method(
                "org.owasp.benchmark.testcode.BenchmarkTest99998.doPost(HttpServletRequest,HttpServletResponse)"
            )
            .with_file_path("src/main/java/org/owasp/benchmark/testcode/BenchmarkTest99998.java")
            .with_source_code(
                'String param = request.getParameter("x");'
                'String sql = "SELECT * from USERS where USERNAME=? and PASSWORD=\'" + bar + "\'";'
                "connection.prepareStatement(sql);"
            )
            .with_annotation("WebServlet")
            .with_analysis_flags(
                {
                    "md5_detected": False,
                    "weak_cipher_detected": False,
                    "insecure_random_detected": False,
                    "sha1prng_detected": False,
                    "path_traversal_detected": False,
                    "command_injection_detected": False,
                    "ldap_injection_detected": False,
                    "xpath_injection_detected": False,
                    "sql_prepare_call_detected": False,
                    "sql_callable_statement_detected": False,
                    "sql_dynamic_query_detected": False,
                }
            )
            .build()
        )

        violations = evaluate_bundle(bundle)
        violation_ids = self._normalized_violation_ids(violations)
        self.assertNotIn("ISO-A.8-SQL-INJECTION", violation_ids)

    def test_evaluate_bundle_still_flags_sql_when_source_analysis_marks_dynamic_query(self) -> None:
        from codegraph.policy.integration import evaluate_bundle

        bundle = (
            BundleBuilder()
            .with_target_method(
                "org.owasp.benchmark.testcode.BenchmarkTest99997.doPost(HttpServletRequest,HttpServletResponse)"
            )
            .with_file_path("src/main/java/org/owasp/benchmark/testcode/BenchmarkTest99997.java")
            .with_source_code(
                'String[] values = request.getParameterValues("x");'
                'String sql = "SELECT * from USERS where USERNAME=? and PASSWORD=\'" + values[0] + "\'";'
                "connection.prepareStatement(sql);"
            )
            .with_annotation("WebServlet")
            .with_analysis_flags(
                {
                    "md5_detected": False,
                    "weak_cipher_detected": False,
                    "insecure_random_detected": False,
                    "sha1prng_detected": False,
                    "path_traversal_detected": False,
                    "command_injection_detected": False,
                    "ldap_injection_detected": False,
                    "xpath_injection_detected": False,
                    "sql_query_uses_tainted_input": True,
                    "sql_query_uses_safe_constant": False,
                    "sql_prepare_call_detected": False,
                    "sql_callable_statement_detected": False,
                    "sql_dynamic_query_detected": True,
                }
            )
            .build()
        )

        violations = evaluate_bundle(bundle)
        violation_ids = self._normalized_violation_ids(violations)
        self.assertIn("ISO-A.8-SQL-INJECTION", violation_ids)

    def test_evaluate_bundle_does_not_flag_sql_for_shape_only_dynamic_query_signal(self) -> None:
        from codegraph.policy.integration import evaluate_bundle

        bundle = (
            BundleBuilder()
            .with_target_method(
                "org.owasp.benchmark.testcode.BenchmarkTest99996.doPost(HttpServletRequest,HttpServletResponse)"
            )
            .with_file_path("src/main/java/org/owasp/benchmark/testcode/BenchmarkTest99996.java")
            .with_source_code(
                'String param = request.getParameter("x");'
                'String bar = "moresafe";'
                "String sql = \"SELECT * from USERS where USERNAME='foo' and PASSWORD='\" + bar + \"'\";"
                "connection.prepareStatement(sql);"
            )
            .with_annotation("WebServlet")
            .with_analysis_flags(
                {
                    "md5_detected": False,
                    "weak_cipher_detected": False,
                    "insecure_random_detected": False,
                    "sha1prng_detected": False,
                    "path_traversal_detected": False,
                    "command_injection_detected": False,
                    "ldap_injection_detected": False,
                    "xpath_injection_detected": False,
                    "sql_query_uses_tainted_input": False,
                    "sql_query_uses_safe_constant": False,
                    "sql_prepare_call_detected": False,
                    "sql_callable_statement_detected": False,
                    "sql_dynamic_query_detected": True,
                }
            )
            .build()
        )

        violations = evaluate_bundle(bundle)
        violation_ids = self._normalized_violation_ids(violations)
        self.assertNotIn("ISO-A.8-SQL-INJECTION", violation_ids)

    def test_evaluate_bundle_suppresses_safe_helper_sql_query(self) -> None:
        from codegraph.policy.integration import evaluate_bundle

        bundle = (
            BundleBuilder()
            .with_target_method(
                "org.owasp.benchmark.testcode.BenchmarkTest99999.doPost(HttpServletRequest,HttpServletResponse)"
            )
            .with_file_path("src/main/java/org/owasp/benchmark/testcode/BenchmarkTest99999.java")
            .with_source_code(
                'String param = request.getHeader("x");'
                "String bar = doSomething(param);"
                'String sql = "select * from users where password=\'" + bar + "\'";'
                "connection.prepareStatement(sql);"
            )
            .with_annotation("WebServlet")
            .with_analysis_flags(
                {
                    "md5_detected": False,
                    "weak_cipher_detected": False,
                    "insecure_random_detected": False,
                    "sha1prng_detected": False,
                    "path_traversal_detected": False,
                    "path_safe_constant_detected": False,
                    "command_injection_detected": False,
                    "ldap_injection_detected": False,
                    "xpath_injection_detected": False,
                    "sql_query_uses_tainted_input": False,
                    "sql_query_uses_safe_constant": False,
                    "sql_prepare_call_detected": False,
                    "sql_callable_statement_detected": False,
                    "sql_dynamic_query_detected": True,
                }
            )
            .with_helper_summaries(
                {
                    "safe_constant_return_vars": ["bar"],
                    "tainted_return_vars": [],
                    "safe_constant_return_used_in_path_sink": False,
                    "safe_constant_return_used_in_ldap_filter": False,
                    "safe_constant_return_used_in_xpath_query": False,
                    "safe_constant_return_used_in_sql_query": True,
                    "safe_constant_return_used_in_command_sink": False,
                    "tainted_return_used_in_xpath_query": False,
                    "tainted_return_used_in_sql_query": False,
                    "tainted_return_used_in_command_sink": False,
                }
            )
            .build()
        )

        violations = evaluate_bundle(bundle)
        violation_ids = self._normalized_violation_ids(violations)
        self.assertNotIn("ISO-A.8-SQL-INJECTION", violation_ids)

    def test_evaluate_bundle_flags_tainted_helper_sql_query(self) -> None:
        from codegraph.policy.integration import evaluate_bundle

        bundle = (
            BundleBuilder()
            .with_target_method(
                "org.owasp.benchmark.testcode.BenchmarkTest99998.doPost(HttpServletRequest,HttpServletResponse)"
            )
            .with_file_path("src/main/java/org/owasp/benchmark/testcode/BenchmarkTest99998.java")
            .with_source_code(
                'String param = request.getHeader("x");'
                "String bar = doSomething(param);"
                'String sql = "select * from users where password=\'" + bar + "\'";'
                "org.owasp.benchmark.helpers.DatabaseHelper.JDBCtemplate.queryForObject(sql, new Object[] {}, String.class);"
            )
            .with_annotation("WebServlet")
            .with_analysis_flags(
                {
                    "md5_detected": False,
                    "weak_cipher_detected": False,
                    "insecure_random_detected": False,
                    "sha1prng_detected": False,
                    "path_traversal_detected": False,
                    "path_safe_constant_detected": False,
                    "command_injection_detected": False,
                    "ldap_injection_detected": False,
                    "xpath_injection_detected": False,
                    "sql_query_uses_tainted_input": False,
                    "sql_query_uses_safe_constant": False,
                    "sql_prepare_call_detected": False,
                    "sql_callable_statement_detected": False,
                    "sql_dynamic_query_detected": False,
                }
            )
            .with_helper_summaries(
                {
                    "safe_constant_return_vars": [],
                    "tainted_return_vars": ["bar"],
                    "safe_constant_return_used_in_path_sink": False,
                    "safe_constant_return_used_in_ldap_filter": False,
                    "safe_constant_return_used_in_xpath_query": False,
                    "safe_constant_return_used_in_sql_query": False,
                    "safe_constant_return_used_in_command_sink": False,
                    "tainted_return_used_in_xpath_query": False,
                    "tainted_return_used_in_sql_query": True,
                    "tainted_return_used_in_command_sink": False,
                }
            )
            .build()
        )

        violations = evaluate_bundle(bundle)
        violation_ids = self._normalized_violation_ids(violations)
        self.assertIn("ISO-A.8-SQL-INJECTION", violation_ids)


if __name__ == "__main__":
    unittest.main()
