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
        self.assertTrue(flags["insecure_random_detected"])
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

    def test_command_injection_detected(self) -> None:
        source = 'String cmd = "echo " + request.getHeader("x"); new ProcessBuilder().command(cmd);'
        flags = analyze_crypto_indicators(source)
        self.assertTrue(flags["command_injection_detected"])

    def test_ldap_injection_detected(self) -> None:
        source = 'String filter = "(&(uid=" + request.getHeader("x") + "))"; InitialDirContext idc = null; idc.search(base, filter, filters, sc);'
        flags = analyze_crypto_indicators(source)
        self.assertTrue(flags["ldap_injection_detected"])

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
