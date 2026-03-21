import unittest

from tests.codegraph.policy._test_helpers import PolicyTestBase, BundleBuilder


class TestCryptoDetection(PolicyTestBase):
    """Tests for cryptographic weakness detection."""

    def test_evaluate_bundle_does_not_flag_random_string_literals_as_insecure_random(self) -> None:
        from codegraph.policy.integration import evaluate_bundle

        bundle = (
            BundleBuilder()
            .with_target_method("org.owasp.benchmark.testcode.BenchmarkTest99999.doPost(HttpServletRequest,HttpServletResponse)")
            .with_file_path("src/main/java/org/owasp/benchmark/testcode/BenchmarkTest99999.java")
            .with_source_code('response.getWriter().println("Weak Randomness Test java.util.Random.nextInt(int) executed");')
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
                }
            )
            .build()
        )

        violations = evaluate_bundle(bundle)
        violation_ids = self._normalized_violation_ids(violations)
        self.assertNotIn("ISO-A.10-WEAK-RANDOM", violation_ids)

    def test_evaluate_bundle_does_not_flag_sha1prng_as_weak_random(self) -> None:
        from codegraph.policy.integration import evaluate_bundle

        bundle = (
            BundleBuilder()
            .with_target_method("org.owasp.benchmark.testcode.BenchmarkTest99996.doPost(HttpServletRequest,HttpServletResponse)")
            .with_file_path("src/main/java/org/owasp/benchmark/testcode/BenchmarkTest99996.java")
            .with_source_code('double value = java.security.SecureRandom.getInstance("SHA1PRNG").nextDouble();')
            .with_analysis_flags(
                {
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
                }
            )
            .build()
        )

        violations = evaluate_bundle(bundle)
        violation_ids = self._normalized_violation_ids(violations)
        self.assertNotIn("ISO-A.10-WEAK-RANDOM", violation_ids)

    def test_evaluate_bundle_flags_sha1_digest_as_weak_hash(self) -> None:
        from codegraph.policy.integration import evaluate_bundle

        bundle = (
            BundleBuilder()
            .with_target_method("org.owasp.benchmark.testcode.BenchmarkTest99997.doPost(HttpServletRequest,HttpServletResponse)")
            .with_file_path("src/main/java/org/owasp/benchmark/testcode/BenchmarkTest99997.java")
            .with_source_code('java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA1", "SUN");')
            .with_analysis_flags(
                {
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
                }
            )
            .build()
        )

        violations = evaluate_bundle(bundle)
        violation_ids = self._normalized_violation_ids(violations)
        self.assertIn("ISO-A.10-WEAK-HASH", violation_ids)


if __name__ == "__main__":
    unittest.main()
