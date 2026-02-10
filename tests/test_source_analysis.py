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


if __name__ == "__main__":
    unittest.main()
