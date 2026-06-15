"""Guard against benchmark-corpus fingerprints in the authoritative Rego layer.

POLICY-C1: an OWASP-Benchmark class-name fingerprint (`benchmarktest`) was
hard-coded into `policy/iso_27001_access.rego` (`benchmark_context`) and used to
gate weak-random detection in `policy/iso_27001_crypto.rego`. Keying an
authoritative decision on the corpus's naming convention is benchmark leakage:
identical insecure code is detected differently solely because of the class name.

This test fails if any Rego module under `policy/` reintroduces a corpus-specific
literal, so the construct-validity fix cannot silently regress.
"""

from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[3]
_POLICY_DIR = _ROOT / "policy"

# Lowercased substrings that would indicate a corpus-name fingerprint baked into
# the authoritative detection logic.
_FORBIDDEN_FINGERPRINTS = ("benchmarktest", "benchmark_context")


@pytest.mark.parametrize("rego_path", sorted(_POLICY_DIR.glob("*.rego")), ids=lambda p: p.name)
def test_rego_has_no_benchmark_fingerprint(rego_path: Path) -> None:
    text = rego_path.read_text(encoding="utf-8").lower()
    for needle in _FORBIDDEN_FINGERPRINTS:
        assert needle not in text, (
            f"{rego_path.name} references corpus fingerprint '{needle}'. The authoritative "
            "Rego layer must not gate decisions on OWASP Benchmark naming conventions "
            "(see audit POLICY-C1)."
        )
