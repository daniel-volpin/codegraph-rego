import unittest
from unittest.mock import patch


class _FakeResult:
    def __init__(self, records):
        self._records = records

    def __iter__(self):
        return iter(self._records)


class _FakeSession:
    def __init__(self, records):
        self._records = records

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def run(self, _cypher, _params):
        return _FakeResult(self._records)


class _FakeDriver:
    def __init__(self, records):
        self._records = records

    def session(self):
        return _FakeSession(self._records)


class TestPolicyEvaluateCaps(unittest.TestCase):
    @staticmethod
    def _normalized_violation_ids(raw_output) -> set[str]:
        from codegraph.policy.integration import normalize_violation_payload

        if isinstance(raw_output, dict):
            payloads = list(raw_output.keys())
        else:
            payloads = list(raw_output)
        normalized = [normalize_violation_payload(item) for item in payloads]
        return {item.get("violation_id") for item in normalized if item}

    def test_is_test_source_path_matches_src_test_only(self) -> None:
        from codegraph.policy.integration import _is_test_source_path

        self.assertTrue(_is_test_source_path("/workspace/project/src/test/java/org/example/FooTest.java"))
        self.assertTrue(_is_test_source_path(r"C:\workspace\project\src\test\java\org\example\FooTest.java"))
        self.assertFalse(_is_test_source_path("/workspace/project/src/main/java/org/example/Foo.java"))
        self.assertFalse(_is_test_source_path(None))

    def test_fetch_methods_with_context_excludes_test_sources(self) -> None:
        from codegraph.policy.integration import _fetch_methods_with_context

        records = [
            {
                "signature": "org.example.TestController.endpoint()",
                "name": "endpoint",
                "file_path": "/workspace/project/src/test/java/org/example/TestController.java",
                "start_line": 10,
                "end_line": 12,
                "modifiers": [],
                "property_annotations": ["GetMapping"],
                "class_fqn": "org.example.TestController",
                "annotation_nodes": ["GetMapping"],
                "uses_fields": [],
                "calls": [],
                "callers": [],
            },
            {
                "signature": "org.example.MainController.endpoint()",
                "name": "endpoint",
                "file_path": "/workspace/project/src/main/java/org/example/MainController.java",
                "start_line": 20,
                "end_line": 24,
                "modifiers": [],
                "property_annotations": ["GetMapping"],
                "class_fqn": "org.example.MainController",
                "annotation_nodes": ["GetMapping"],
                "uses_fields": [],
                "calls": [],
                "callers": [],
            },
        ]

        snapshots = _fetch_methods_with_context(_FakeDriver(records))

        self.assertEqual(len(snapshots), 1)
        self.assertEqual(snapshots[0]["signature"], "org.example.MainController.endpoint()")

    def test_evaluate_bundle_does_not_flag_random_string_literals_as_insecure_random(self) -> None:
        from codegraph.policy.integration import evaluate_bundle

        bundle = {
            "target_method": "org.owasp.benchmark.testcode.BenchmarkTest99999.doPost(HttpServletRequest,HttpServletResponse)",
            "file_path": "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest99999.java",
            "source_code": 'response.getWriter().println("Weak Randomness Test java.util.Random.nextInt(int) executed");',
            "graph_context": {"annotations": [], "uses_fields": [], "calls": [], "callers": []},
            "analysis_flags": {
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
            },
        }

        violations = evaluate_bundle(bundle)
        violation_ids = self._normalized_violation_ids(violations)
        self.assertNotIn("ISO-A.10-WEAK-RANDOM", violation_ids)

    def test_evaluate_bundle_does_not_flag_sha1prng_as_weak_random(self) -> None:
        from codegraph.policy.integration import evaluate_bundle

        bundle = {
            "target_method": "org.owasp.benchmark.testcode.BenchmarkTest99996.doPost(HttpServletRequest,HttpServletResponse)",
            "file_path": "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest99996.java",
            "source_code": 'double value = java.security.SecureRandom.getInstance("SHA1PRNG").nextDouble();',
            "graph_context": {"annotations": [], "uses_fields": [], "calls": [], "callers": []},
            "analysis_flags": {
                "md5_detected": False,
                "weak_cipher_detected": False,
                "insecure_random_detected": False,
                "sha1prng_detected": True,
                "path_traversal_detected": False,
                "path_safe_constant_detected": False,
                "command_injection_detected": False,
                "ldap_injection_detected": False,
                "xpath_injection_detected": False,
                "sql_prepare_call_detected": False,
                "sql_callable_statement_detected": False,
            },
        }

        violations = evaluate_bundle(bundle)
        violation_ids = self._normalized_violation_ids(violations)
        self.assertNotIn("ISO-A.10-WEAK-RANDOM", violation_ids)

    def test_evaluate_bundle_flags_sha1_digest_as_weak_hash(self) -> None:
        from codegraph.policy.integration import evaluate_bundle

        bundle = {
            "target_method": "org.owasp.benchmark.testcode.BenchmarkTest99997.doPost(HttpServletRequest,HttpServletResponse)",
            "file_path": "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest99997.java",
            "source_code": 'java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA1", "SUN");',
            "graph_context": {"annotations": [], "uses_fields": [], "calls": [], "callers": []},
            "analysis_flags": {
                "md5_detected": False,
                "weak_hash_detected": True,
                "weak_cipher_detected": False,
                "insecure_random_detected": False,
                "sha1prng_detected": False,
                "path_traversal_detected": False,
                "command_injection_detected": False,
                "ldap_injection_detected": False,
                "xpath_injection_detected": False,
                "sql_prepare_call_detected": False,
                "sql_callable_statement_detected": False,
            },
        }

        violations = evaluate_bundle(bundle)
        violation_ids = self._normalized_violation_ids(violations)
        self.assertIn("ISO-A.10-WEAK-HASH", violation_ids)

    def test_evaluate_bundle_respects_clean_path_flag_over_source_fallback(self) -> None:
        from codegraph.policy.integration import evaluate_bundle

        bundle = {
            "target_method": "org.owasp.benchmark.testcode.BenchmarkTest99995.doPost(HttpServletRequest,HttpServletResponse)",
            "file_path": "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest99995.java",
            "source_code": (
                'String param = request.getHeader("x");'
                'String bar = "alsosafe";'
                'String fileName = base + bar;'
                "new java.io.FileOutputStream(fileName);"
            ),
            "graph_context": {"annotations": ["WebServlet"], "uses_fields": [], "calls": [], "callers": []},
            "analysis_flags": {
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
            },
        }

        violations = evaluate_bundle(bundle)
        violation_ids = self._normalized_violation_ids(violations)
        self.assertNotIn("ISO-A.8-PATH-TRAVERSAL", violation_ids)

    def test_evaluate_bundle_suppresses_safe_helper_direct_path_sink(self) -> None:
        from codegraph.policy.integration import evaluate_bundle

        bundle = {
            "target_method": "org.owasp.benchmark.testcode.BenchmarkTest99991.doPost(HttpServletRequest,HttpServletResponse)",
            "file_path": "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest99991.java",
            "source_code": (
                'String param = request.getHeader("x");'
                "String bar = doSomething(param);"
                "new java.io.File(bar);"
            ),
            "graph_context": {"annotations": ["WebServlet"], "uses_fields": [], "calls": [], "callers": []},
            "analysis_flags": {
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
            },
            "helper_summaries": {
                "safe_constant_return_vars": ["bar"],
                "tainted_return_vars": [],
                "safe_constant_return_used_in_path_sink": True,
                "safe_constant_return_used_in_ldap_filter": False,
                "safe_constant_return_used_in_command_sink": False,
            },
        }

        violations = evaluate_bundle(bundle)
        violation_ids = self._normalized_violation_ids(violations)
        self.assertNotIn("ISO-A.8-PATH-TRAVERSAL", violation_ids)

    def test_evaluate_bundle_respects_safe_resource_path_flag(self) -> None:
        from codegraph.policy.integration import evaluate_bundle

        bundle = {
            "target_method": "org.owasp.benchmark.testcode.BenchmarkTest99990.doPost(HttpServletRequest,HttpServletResponse)",
            "file_path": "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest99990.java",
            "source_code": (
                'String param = request.getHeader("x");'
                'new java.io.FileInputStream(org.owasp.benchmark.helpers.Utils.getFileFromClasspath("employees.xml", this.getClass().getClassLoader()));'
            ),
            "graph_context": {"annotations": ["WebServlet"], "uses_fields": [], "calls": [], "callers": []},
            "analysis_flags": {
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
            },
        }

        violations = evaluate_bundle(bundle)
        violation_ids = self._normalized_violation_ids(violations)
        self.assertNotIn("ISO-A.8-PATH-TRAVERSAL", violation_ids)

    def test_evaluate_bundle_does_not_retrigger_path_source_fallback_when_flags_present(self) -> None:
        from codegraph.policy.integration import evaluate_bundle

        bundle = {
            "target_method": "org.owasp.benchmark.testcode.BenchmarkTest99989.doPost(HttpServletRequest,HttpServletResponse)",
            "file_path": "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest99989.java",
            "source_code": (
                'String param = request.getHeader("x");'
                'String bar = "alsosafe";'
                'String fileName = base + bar;'
                "new java.io.FileOutputStream(fileName);"
            ),
            "graph_context": {"annotations": ["WebServlet"], "uses_fields": [], "calls": [], "callers": []},
            "analysis_flags": {
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
            },
        }

        violations = evaluate_bundle(bundle)
        violation_ids = self._normalized_violation_ids(violations)
        self.assertNotIn("ISO-A.8-PATH-TRAVERSAL", violation_ids)

    def test_evaluate_bundle_flags_command_payload_taint(self) -> None:
        from codegraph.policy.integration import evaluate_bundle

        bundle = {
            "target_method": "org.owasp.benchmark.testcode.BenchmarkTest99990.doPost(HttpServletRequest,HttpServletResponse)",
            "file_path": "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest99990.java",
            "source_code": (
                'String param = request.getHeader("x");'
                'String cmd = "echo " + param;'
                "Runtime.getRuntime().exec(cmd);"
            ),
            "graph_context": {"annotations": ["WebServlet"], "uses_fields": [], "calls": [], "callers": []},
            "analysis_flags": {
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
            },
        }

        violations = evaluate_bundle(bundle)
        violation_ids = self._normalized_violation_ids(violations)
        self.assertIn("ISO-A.8-CMD-INJECTION", violation_ids)

    def test_evaluate_bundle_does_not_flag_command_env_only_taint(self) -> None:
        from codegraph.policy.integration import evaluate_bundle

        bundle = {
            "target_method": "org.owasp.benchmark.testcode.BenchmarkTest99989.doPost(HttpServletRequest,HttpServletResponse)",
            "file_path": "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest99989.java",
            "source_code": (
                'String param = request.getHeader("x");'
                'String cmd = "ls";'
                'String[] argsEnv = {param};'
                "Runtime.getRuntime().exec(cmd, argsEnv);"
            ),
            "graph_context": {"annotations": ["WebServlet"], "uses_fields": [], "calls": [], "callers": []},
            "analysis_flags": {
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
            },
            "helper_summaries": {
                "safe_constant_return_vars": [],
                "tainted_return_vars": [],
                "safe_constant_return_used_in_path_sink": False,
                "safe_constant_return_used_in_ldap_filter": False,
                "safe_constant_return_used_in_command_sink": False,
                "tainted_return_used_in_command_sink": False,
            },
        }

        violations = evaluate_bundle(bundle)
        violation_ids = self._normalized_violation_ids(violations)
        self.assertNotIn("ISO-A.8-CMD-INJECTION", violation_ids)

    def test_evaluate_bundle_flags_tainted_helper_command_payload(self) -> None:
        from codegraph.policy.integration import evaluate_bundle

        bundle = {
            "target_method": "org.owasp.benchmark.testcode.BenchmarkTest99988.doPost(HttpServletRequest,HttpServletResponse)",
            "file_path": "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest99988.java",
            "source_code": (
                'String param = request.getHeader("x");'
                "String bar = doSomething(param);"
                'String[] args = new String[] {"sh", "-c", "ls " + bar};'
                "Runtime.getRuntime().exec(args);"
            ),
            "graph_context": {"annotations": ["WebServlet"], "uses_fields": [], "calls": [], "callers": []},
            "analysis_flags": {
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
            },
            "helper_summaries": {
                "safe_constant_return_vars": [],
                "tainted_return_vars": ["bar"],
                "safe_constant_return_used_in_path_sink": False,
                "safe_constant_return_used_in_ldap_filter": False,
                "safe_constant_return_used_in_command_sink": False,
                "tainted_return_used_in_command_sink": True,
            },
        }

        violations = evaluate_bundle(bundle)
        violation_ids = self._normalized_violation_ids(violations)
        self.assertIn("ISO-A.8-CMD-INJECTION", violation_ids)

    def test_evaluate_bundle_suppresses_safe_helper_command_payload(self) -> None:
        from codegraph.policy.integration import evaluate_bundle

        bundle = {
            "target_method": "org.owasp.benchmark.testcode.BenchmarkTest99987.doPost(HttpServletRequest,HttpServletResponse)",
            "file_path": "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest99987.java",
            "source_code": (
                'String param = request.getHeader("x");'
                "String bar = doSomething(param);"
                'String[] args = new String[] {"sh", "-c", "ls " + bar};'
                "ProcessBuilder pb = new ProcessBuilder();"
                "pb.command(args);"
            ),
            "graph_context": {"annotations": ["WebServlet"], "uses_fields": [], "calls": [], "callers": []},
            "analysis_flags": {
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
            },
            "helper_summaries": {
                "safe_constant_return_vars": ["bar"],
                "tainted_return_vars": [],
                "safe_constant_return_used_in_path_sink": False,
                "safe_constant_return_used_in_ldap_filter": False,
                "safe_constant_return_used_in_command_sink": True,
                "tainted_return_used_in_command_sink": False,
            },
        }

        violations = evaluate_bundle(bundle)
        violation_ids = self._normalized_violation_ids(violations)
        self.assertNotIn("ISO-A.8-CMD-INJECTION", violation_ids)

    def test_evaluate_bundle_suppresses_safe_helper_ldap_filter(self) -> None:
        from codegraph.policy.integration import evaluate_bundle

        bundle = {
            "target_method": "org.owasp.benchmark.testcode.BenchmarkTest99993.doPost(HttpServletRequest,HttpServletResponse)",
            "file_path": "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest99993.java",
            "source_code": (
                'String param = request.getHeader("x");'
                "String bar = doSomething(param);"
                'String filter = "(&(uid=" + bar + "))";'
                "InitialDirContext idc = null; idc.search(base, filter, filters, sc);"
            ),
            "graph_context": {"annotations": ["WebServlet"], "uses_fields": [], "calls": [], "callers": []},
            "analysis_flags": {
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
            },
            "helper_summaries": {
                "safe_constant_return_vars": ["bar"],
                "tainted_return_vars": [],
                "safe_constant_return_used_in_path_sink": False,
                "safe_constant_return_used_in_ldap_filter": True,
                "safe_constant_return_used_in_command_sink": False,
            },
        }

        violations = evaluate_bundle(bundle)
        violation_ids = self._normalized_violation_ids(violations)
        self.assertNotIn("ISO-A.8-LDAP-INJECTION", violation_ids)

    def test_evaluate_bundle_does_not_suppress_tainted_helper_ldap_filter(self) -> None:
        from codegraph.policy.integration import evaluate_bundle

        bundle = {
            "target_method": "org.owasp.benchmark.testcode.BenchmarkTest99992.doPost(HttpServletRequest,HttpServletResponse)",
            "file_path": "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest99992.java",
            "source_code": (
                'String param = request.getHeader("x");'
                "String bar = doSomething(param);"
                'String filter = "(&(uid=" + bar + "))";'
                "InitialDirContext idc = null; idc.search(base, filter, filters, sc);"
            ),
            "graph_context": {"annotations": ["WebServlet"], "uses_fields": [], "calls": [], "callers": []},
            "analysis_flags": {
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
            },
            "helper_summaries": {
                "safe_constant_return_vars": [],
                "tainted_return_vars": ["bar"],
                "safe_constant_return_used_in_path_sink": False,
                "safe_constant_return_used_in_ldap_filter": False,
                "safe_constant_return_used_in_command_sink": False,
            },
        }

        violations = evaluate_bundle(bundle)
        violation_ids = self._normalized_violation_ids(violations)
        self.assertIn("ISO-A.8-LDAP-INJECTION", violation_ids)

    def test_evaluate_bundle_can_fallback_to_source_for_path_traversal_when_flags_missing(self) -> None:
        from codegraph.policy.integration import evaluate_bundle

        bundle = {
            "target_method": "org.owasp.benchmark.testcode.BenchmarkTest99994.doPost(HttpServletRequest,HttpServletResponse)",
            "file_path": "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest99994.java",
            "source_code": (
                'String param = request.getHeader("x");'
                'String fileName = base + param;'
                "new java.io.FileInputStream(fileName);"
            ),
            "graph_context": {"annotations": ["WebServlet"], "uses_fields": [], "calls": [], "callers": []},
            "analysis_flags": None,
        }

        violations = evaluate_bundle(bundle)
        violation_ids = self._normalized_violation_ids(violations)
        self.assertIn("ISO-A.8-PATH-TRAVERSAL", violation_ids)

    def test_evaluate_bundle_does_not_use_sql_fallback_for_placeholder_prepared_statement(self) -> None:
        from codegraph.policy.integration import evaluate_bundle

        bundle = {
            "target_method": "org.owasp.benchmark.testcode.BenchmarkTest99998.doPost(HttpServletRequest,HttpServletResponse)",
            "file_path": "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest99998.java",
            "source_code": (
                'String param = request.getParameter("x");'
                'String sql = "SELECT * from USERS where USERNAME=? and PASSWORD=\'" + bar + "\'";'
                "connection.prepareStatement(sql);"
            ),
            "graph_context": {"annotations": ["WebServlet"], "uses_fields": [], "calls": [], "callers": []},
            "analysis_flags": {
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
            },
        }

        violations = evaluate_bundle(bundle)
        violation_ids = self._normalized_violation_ids(violations)
        self.assertNotIn("ISO-A.8-SQL-INJECTION", violation_ids)

    def test_evaluate_bundle_still_flags_sql_when_source_analysis_marks_dynamic_query(self) -> None:
        from codegraph.policy.integration import evaluate_bundle

        bundle = {
            "target_method": "org.owasp.benchmark.testcode.BenchmarkTest99997.doPost(HttpServletRequest,HttpServletResponse)",
            "file_path": "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest99997.java",
            "source_code": (
                'String[] values = request.getParameterValues("x");'
                'String sql = "SELECT * from USERS where USERNAME=? and PASSWORD=\'" + values[0] + "\'";'
                "connection.prepareStatement(sql);"
            ),
            "graph_context": {"annotations": ["WebServlet"], "uses_fields": [], "calls": [], "callers": []},
            "analysis_flags": {
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
                "sql_dynamic_query_detected": True,
            },
        }

        violations = evaluate_bundle(bundle)
        violation_ids = self._normalized_violation_ids(violations)
        self.assertIn("ISO-A.8-SQL-INJECTION", violation_ids)

    @patch("codegraph.policy.integration.get_policy_catalog_entries", return_value=[])
    @patch("codegraph.policy.integration.load_iso_rules", return_value={})
    @patch("codegraph.policy.integration.load_policy_catalog", return_value={})
    @patch("codegraph.policy.integration._resolve_catalog_entry", return_value=None)
    @patch("codegraph.policy.integration.shutil.which", return_value="/usr/local/bin/opa")
    def test_default_behavior_has_no_limit_metadata(
        self,
        _mock_which,
        _mock_resolve_catalog,
        _mock_load_catalog,
        _mock_load_rules,
        _mock_catalog_entries,
    ) -> None:
        from codegraph.policy.integration import evaluate_policies

        bundles = [
            {"target_method": "m1", "file_path": "f1", "source_code": "", "graph_context": {}, "vector_context": []},
            {"target_method": "m2", "file_path": "f2", "source_code": "", "graph_context": {}, "vector_context": []},
        ]
        with (
            patch("codegraph.policy.integration.build_policy_input", return_value={"bundles": bundles}),
            patch(
                "codegraph.policy.integration._evaluate_bundle",
                return_value=[{"violation_id": "A", "reason": "r", "severity": "high"}],
            ),
        ):
            result = evaluate_policies()

        self.assertIn("violations", result)
        self.assertNotIn("limits", result)
        self.assertNotIn("truncated", result)
        self.assertNotIn("violation_counts_by_id", result)
        self.assertEqual(len(result["violations"]), 2)

    @patch("codegraph.policy.integration.get_policy_catalog_entries", return_value=[])
    @patch("codegraph.policy.integration.load_iso_rules", return_value={})
    @patch("codegraph.policy.integration.load_policy_catalog", return_value={})
    @patch("codegraph.policy.integration._resolve_catalog_entry", return_value=None)
    @patch("codegraph.policy.integration.shutil.which", return_value="/usr/local/bin/opa")
    def test_caps_total_and_per_violation_id_and_early_stop(
        self,
        _mock_which,
        _mock_resolve_catalog,
        _mock_load_catalog,
        _mock_load_rules,
        _mock_catalog_entries,
    ) -> None:
        from codegraph.policy.integration import evaluate_policies

        bundles = [
            {"target_method": "m1", "file_path": "f1", "source_code": "", "graph_context": {}, "vector_context": []},
            {"target_method": "m2", "file_path": "f2", "source_code": "", "graph_context": {}, "vector_context": []},
            {"target_method": "m3", "file_path": "f3", "source_code": "", "graph_context": {}, "vector_context": []},
            {"target_method": "m4", "file_path": "f4", "source_code": "", "graph_context": {}, "vector_context": []},
        ]

        def bundle_side_effect(_bundle):
            # Bundle 1 yields A,B; bundle 2 yields A,C; bundle 3 yields D; bundle 4 should not be called.
            if _bundle["target_method"] == "m1":
                return [{"violation_id": "A"}] * 200 + [{"violation_id": "B"}] * 200
            if _bundle["target_method"] == "m2":
                return [{"violation_id": "A"}] * 200 + [{"violation_id": "C"}] * 200
            if _bundle["target_method"] == "m3":
                return [{"violation_id": "D"}] * 200
            return [{"violation_id": "Z"}] * 200

        with (
            patch("codegraph.policy.integration.build_policy_input", return_value={"bundles": bundles}),
            patch(
                "codegraph.policy.integration._evaluate_bundle",
                side_effect=bundle_side_effect,
            ) as mock_eval,
        ):
            result = evaluate_policies(max_total_violations=100, max_per_violation_id=25)

        self.assertIn("limits", result)
        self.assertTrue(result.get("truncated"))
        self.assertLessEqual(len(result["violations"]), 100)

        counts = {}
        for v in result["violations"]:
            vid = str(v.get("violation_id"))
            counts[vid] = counts.get(vid, 0) + 1
        self.assertTrue(all(count <= 25 for count in counts.values()))

        # Under concurrent evaluation, all bundles are submitted eagerly (no early abort of
        # in-flight subprocesses). The caps are applied when collecting results, so the output
        # must still respect both total and per-violation-id limits.
        self.assertEqual(mock_eval.call_count, len(bundles))

    @patch("codegraph.policy.integration.get_policy_catalog_entries", return_value=[])
    @patch("codegraph.policy.integration.load_iso_rules", return_value={})
    @patch("codegraph.policy.integration.load_policy_catalog", return_value={})
    @patch("codegraph.policy.integration._resolve_catalog_entry", return_value=None)
    @patch("codegraph.policy.integration.shutil.which", return_value="/usr/local/bin/opa")
    def test_policy_results_expose_top_level_code_snippet_fields(
        self,
        _mock_which,
        _mock_resolve_catalog,
        _mock_load_catalog,
        _mock_load_rules,
        _mock_catalog_entries,
    ) -> None:
        from codegraph.policy.integration import evaluate_policies

        bundles = [
            {
                "target_method": "m1",
                "file_path": "f1",
                "source_code": "public void m1() {}",
                "graph_context": {},
                "vector_context": [],
                "start_line": 10,
                "end_line": 12,
                "analysis_flags": {"md5_detected": False},
            }
        ]

        with (
            patch("codegraph.policy.integration.build_policy_input", return_value={"bundles": bundles}),
            patch(
                "codegraph.policy.integration._evaluate_bundle",
                return_value=[{"violation_id": "A", "reason": "r", "severity": "high"}],
            ),
        ):
            result = evaluate_policies()

        violation = result["violations"][0]
        self.assertEqual(violation["code_snippet"], "public void m1() {}")
        self.assertTrue(violation["snippet_available"])
        self.assertEqual(violation["snippet_start_line"], 10)
        self.assertEqual(violation["snippet_end_line"], 12)
        self.assertEqual(violation["evidence"]["source_code"], "public void m1() {}")

    @patch("codegraph.policy.integration.get_policy_catalog_entries", return_value=[])
    @patch("codegraph.policy.integration.load_iso_rules", return_value={})
    @patch("codegraph.policy.integration.load_policy_catalog", return_value={})
    @patch("codegraph.policy.integration._resolve_catalog_entry", return_value=None)
    @patch("codegraph.policy.integration.shutil.which", return_value="/usr/local/bin/opa")
    def test_policy_results_include_remediation_capability_metadata(
        self,
        _mock_which,
        _mock_resolve_catalog,
        _mock_load_catalog,
        _mock_load_rules,
        _mock_catalog_entries,
    ) -> None:
        from codegraph.policy.integration import evaluate_policies

        bundles = [
            {"target_method": "m1", "file_path": "src/main/java/F1.java", "source_code": "", "graph_context": {}, "vector_context": []},
            {"target_method": "m2", "file_path": "src/main/java/F2.java", "source_code": "", "graph_context": {}, "vector_context": []},
            {"target_method": "m3", "file_path": "src/main/java/F3.java", "source_code": "", "graph_context": {}, "vector_context": []},
        ]

        with (
            patch("codegraph.policy.integration.build_policy_input", return_value={"bundles": bundles}),
            patch(
                "codegraph.policy.integration._evaluate_bundle",
                side_effect=[
                    [{"violation_id": "ISO-A.10-WEAK-HASH", "reason": "r1", "severity": "high"}],
                    [{"violation_id": "ISO-A.10-WEAK-RANDOM", "reason": "r3", "severity": "high"}],
                    [{"violation_id": "ISO-A.9.4.1", "reason": "r2", "severity": "high"}],
                ],
            ),
        ):
            result = evaluate_policies()

        violations = result["violations"]
        supported = next(v for v in violations if v["violation_id"] == "ISO-A.10-WEAK-HASH")
        random_supported = next(v for v in violations if v["violation_id"] == "ISO-A.10-WEAK-RANDOM")
        unsupported = next(v for v in violations if v["violation_id"] == "ISO-A.9.4.1")

        self.assertEqual(
            supported["remediation"],
            {
                "supported": True,
                "support_tier": "full",
                "reason_code": "supported_rule_for_auto_fix",
                "strategy": "llm_method_replacement",
                "preview_available": True,
                "verify_available": True,
                "ui_apply_mode": "dry_run",
                "rationale": "Bounded weak-hash replacements such as MD5 or SHA-1 to SHA-256 can be applied with minimal local edits.",
                "safe_refusal_possible": False,
            },
        )
        self.assertEqual(
            random_supported["remediation"],
            {
                "supported": True,
                "support_tier": "full",
                "reason_code": "supported_rule_for_auto_fix",
                "strategy": "llm_method_replacement",
                "preview_available": True,
                "verify_available": True,
                "ui_apply_mode": "dry_run",
                "rationale": "Local randomness upgrades can often be made safely with narrow replacements to SecureRandom-based APIs.",
                "safe_refusal_possible": True,
            },
        )
        self.assertEqual(
            unsupported["remediation"],
            {
                "supported": False,
                "support_tier": "manual",
                "reason_code": "unsupported_rule_for_auto_fix",
                "strategy": None,
                "preview_available": False,
                "verify_available": False,
                "ui_apply_mode": "dry_run",
                "rationale": "Access-control findings remain manual-review because endpoint semantics cannot be safely inferred from method-local evidence.",
                "safe_refusal_possible": False,
            },
        )

    @patch("codegraph.policy.integration.get_policy_catalog_entries", return_value=[])
    @patch("codegraph.policy.integration.load_iso_rules", return_value={})
    @patch("codegraph.policy.integration.load_policy_catalog", return_value={})
    @patch("codegraph.policy.integration._resolve_catalog_entry", return_value=None)
    @patch("codegraph.policy.integration.shutil.which", return_value="/usr/local/bin/opa")
    def test_policy_results_can_be_filtered_by_rule_ids(
        self,
        _mock_which,
        _mock_resolve_catalog,
        _mock_load_catalog,
        _mock_load_rules,
        _mock_catalog_entries,
    ) -> None:
        from codegraph.policy.integration import evaluate_policies

        bundles = [
            {"target_method": "m1", "file_path": "src/main/java/F1.java", "source_code": "", "graph_context": {}, "vector_context": []},
            {"target_method": "m2", "file_path": "src/main/java/F2.java", "source_code": "", "graph_context": {}, "vector_context": []},
        ]

        with (
            patch("codegraph.policy.integration.build_policy_input", return_value={"bundles": bundles}),
            patch(
                "codegraph.policy.integration._evaluate_bundle",
                side_effect=[
                    [{"violation_id": "ISO-A.10-WEAK-HASH", "reason": "hash", "severity": "high"}],
                    [{"violation_id": "ISO-A.8-SQL-INJECTION", "reason": "sql", "severity": "high"}],
                ],
            ),
        ):
            result = evaluate_policies(rule_ids=["ISO-A.10-WEAK-HASH"])

        self.assertEqual(len(result["violations"]), 1)
        self.assertEqual(result["violations"][0]["violation_id"], "ISO-A.10-WEAK-HASH")


if __name__ == "__main__":
    unittest.main()
