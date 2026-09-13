"""An unreadable recorded source must fail closed with a structured error.

A method snapshot carries the path and hash of the source it was parsed from. If
that file is gone — the analysed workspace was temporary — or its bytes no longer
match the recorded hash, ``_extract_method_source`` raises ``ValueError``. That
raise used to travel out of ``evaluate_policies`` uncaught, so ``GET
/policy/evaluate`` answered ``{"error": "internal"}`` with no way for an operator
to tell a vanished workspace from a genuine crash.

Failing closed is correct: evaluating the readable subset would silently
understate findings. Only the reporting was wrong.
"""

from __future__ import annotations

import pytest

from codegraph.policy import integration


@pytest.fixture
def _opa_present(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(integration.shutil, "which", lambda _name: "/usr/local/bin/opa")


@pytest.mark.parametrize(
    "reason",
    ["policy_source_unavailable", "policy_source_hash_mismatch"],
)
def test_unreadable_source_returns_structured_error(
    reason: str,
    _opa_present: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def _raise(**_kwargs: object) -> dict[str, object]:
        raise ValueError(reason)

    monkeypatch.setattr(integration, "build_policy_input", _raise)

    result = integration.evaluate_policies(workspace_root="/tmp/gone")

    assert result["error"] == f"policy_evidence_unavailable: {reason}"
    assert result["workspace_root"] == "/tmp/gone"
    assert "re-ingest" in result["hint"].lower()
    # fail closed: no partial findings that would read as "nothing wrong here"
    assert "violations" not in result


def test_other_errors_are_not_swallowed(_opa_present: None, monkeypatch: pytest.MonkeyPatch) -> None:
    """Only ValueError is an expected evidence condition; the rest must propagate."""

    def _raise(**_kwargs: object) -> dict[str, object]:
        raise RuntimeError("neo4j unreachable")

    monkeypatch.setattr(integration, "build_policy_input", _raise)

    with pytest.raises(RuntimeError, match="neo4j unreachable"):
        integration.evaluate_policies()
