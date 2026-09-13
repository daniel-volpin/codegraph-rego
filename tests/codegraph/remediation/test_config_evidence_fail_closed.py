"""A recheck that cannot see config evidence must refuse, not report "fixed".

Candidates are re-evaluated from a virtual snapshot with no call evidence, so a
finding decided on a resolved configuration value cannot be reproduced there.
Reporting such a candidate as fixed would clear the policy gate without
re-examining anything — the same failure that made an OPA-only recheck report
engine-owned findings as fixed.
"""

from __future__ import annotations

import pytest

from codegraph.remediation.service import _assert_recheck_can_reproduce_evidence


def _context(resolved):
    return {"rule_id": "ISO-A.10-WEAK-HASH", "evidence": {"config_context": {"resolved": resolved}}}


def test_config_backed_finding_refuses_recheck() -> None:
    context = _context(
        [{"key": "hashAlg1", "value": "MD5", "source_file": "benchmark.properties", "line": 4}]
    )
    with pytest.raises(RuntimeError, match="candidate_reverification_requires_config_evidence"):
        _assert_recheck_can_reproduce_evidence(context)


@pytest.mark.parametrize(
    "evidence",
    [
        {},
        {"config_context": {}},
        {"config_context": {"resolved": []}},
        {"config_context": None},
    ],
)
def test_findings_without_config_evidence_recheck_normally(evidence) -> None:
    """Only config-dependent findings are refused; everything else is unaffected."""
    _assert_recheck_can_reproduce_evidence({"rule_id": "ISO-A.10-WEAK-HASH", "evidence": evidence})


def test_missing_evidence_is_not_an_error() -> None:
    _assert_recheck_can_reproduce_evidence({"rule_id": "X"})
