"""Crypto and hash controls must decide on the configured algorithm.

OWASP Benchmark selects the algorithm through a properties file, and the
in-source defaults point the wrong way in both directions: the weak case
defaults to a strong algorithm, the safe case defaults to a weak one. Deciding
on the declared value is therefore the only correct resolution, and deciding on
the source default would produce false negatives and false positives at once.
"""

from __future__ import annotations

import shutil
import unittest

import pytest

from tests.codegraph.policy._test_helpers import BundleBuilder, PolicyTestBase

OPA_AVAILABLE = shutil.which("opa") is not None

_HASH_RULE = "ISO-A.10-WEAK-HASH"
_CRYPTO_RULE = "ISO-A.10-WEAK-CRYPTO"

# The values OWASP Benchmark's benchmark.properties actually declares.
_HASH_WEAK = {"key": "hashAlg1", "value": "MD5", "source_file": "benchmark.properties", "line": 4}
_HASH_STRONG = {"key": "hashAlg2", "value": "SHA-256", "source_file": "benchmark.properties", "line": 5}
_CIPHER_WEAK = {
    "key": "cryptoAlg1",
    "value": "DES/ECB/PKCS5Padding",
    "source_file": "benchmark.properties",
    "line": 2,
}
_CIPHER_STRONG = {
    "key": "cryptoAlg2",
    "value": "AES/CCM/NoPadding",
    "source_file": "benchmark.properties",
    "line": 3,
}

_HASH_SOURCE = 'String a = p.getProperty("hashAlg1", "SHA512"); MessageDigest.getInstance(a);'
_CIPHER_SOURCE = 'String a = p.getProperty("cryptoAlg1", "AES/ECB/PKCS5Padding"); Cipher.getInstance(a);'


def _evaluate(source: str, *resolved: dict) -> set[str]:
    from codegraph.policy.runtime.opa import evaluate_bundle

    bundle = (
        BundleBuilder()
        .with_target_method("com.example.Svc.run()")
        .with_file_path("src/main/java/com/example/Svc.java")
        .with_source_code(source)
        .with_config_context(*resolved)
        .build()
    )
    return PolicyTestBase._normalized_violation_ids(evaluate_bundle(bundle))


@unittest.skipUnless(OPA_AVAILABLE, "opa not installed")
class TestConfiguredAlgorithmDecides(unittest.TestCase):
    def test_weak_configured_hash_is_flagged(self) -> None:
        assert _HASH_RULE in _evaluate(_HASH_SOURCE, _HASH_WEAK)

    def test_strong_configured_hash_is_not_flagged(self) -> None:
        """The source default here is 'SHA512'; only the declared value decides."""
        assert _HASH_RULE not in _evaluate(
            'String a = p.getProperty("hashAlg2", "SHA5"); MessageDigest.getInstance(a);',
            _HASH_STRONG,
        )

    def test_weak_configured_cipher_is_flagged(self) -> None:
        assert _CRYPTO_RULE in _evaluate(_CIPHER_SOURCE, _CIPHER_WEAK)

    def test_strong_configured_cipher_is_not_flagged_despite_weak_default(self) -> None:
        """Source default is AES/ECB (weak); the declared value AES/CCM is not."""
        assert _CRYPTO_RULE not in _evaluate(
            'String a = p.getProperty("cryptoAlg2", "AES/ECB/PKCS5Padding"); Cipher.getInstance(a);',
            _CIPHER_STRONG,
        )

    def test_ecb_mode_alone_is_weak(self) -> None:
        assert _CRYPTO_RULE in _evaluate(
            _CIPHER_SOURCE,
            {"key": "c", "value": "AES/ECB/PKCS5Padding", "source_file": "a.properties", "line": 1},
        )


@unittest.skipUnless(OPA_AVAILABLE, "opa not installed")
class TestPrecisionIsPreserved(unittest.TestCase):
    def test_unresolved_config_stays_silent(self) -> None:
        """A key built at runtime does not resolve, so nothing is asserted."""
        assert _evaluate(_HASH_SOURCE) == set() or _HASH_RULE not in _evaluate(_HASH_SOURCE)

    def test_weak_value_without_a_consuming_api_is_not_flagged(self) -> None:
        """Reading an unrelated weak-valued property is not a crypto finding."""
        source = 'String greeting = p.getProperty("hashAlg1"); log(greeting);'
        found = _evaluate(source, _HASH_WEAK)
        assert _HASH_RULE not in found
        assert _CRYPTO_RULE not in found

    def test_hash_config_does_not_leak_into_the_cipher_rule(self) -> None:
        assert _CRYPTO_RULE not in _evaluate(_HASH_SOURCE, _HASH_WEAK)


if __name__ == "__main__":
    pytest.main([__file__])
