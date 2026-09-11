from __future__ import annotations

import pytest

from codegraph.llm.services.remediation_generation_service import RemediationGenerationService
from codegraph.llm.tasks.remediation import RemediationTaskSpec


def _context() -> dict[str, object]:
    return {
        "target_method": "com.example.Foo.hash()",
        "exact_method_source": 'public void hash() { java.security.MessageDigest.getInstance("MD5"); }',
        "remediation_plan": None,
    }


def _spec() -> RemediationTaskSpec:
    return RemediationTaskSpec(
        rule_id="ISO-A.10-WEAK-HASH",
        objective="Replace MD5 with SHA-256",
        allowed_transformations=[],
        non_goals=[],
    )


def test_internal_type_error_from_supported_client_is_not_retried() -> None:
    call_count = 0

    def modern_client(messages, **kwargs):  # noqa: ANN001,ARG001
        nonlocal call_count
        call_count += 1
        raise TypeError("internal parser exploded")

    service = RemediationGenerationService(llm_client=modern_client)
    with pytest.raises(TypeError, match="internal parser exploded"):
        service.propose_method_edits(context=_context(), spec=_spec())
    assert call_count == 1


def test_legacy_client_without_structured_kwargs_is_called_once() -> None:
    call_count = 0

    def legacy_client(messages, *, task_type="", retry_index=0):  # noqa: ANN001,ARG001
        nonlocal call_count
        call_count += 1
        return '{"decision":"no_fix","edits":[],"reason":"legacy"}'

    service = RemediationGenerationService(llm_client=legacy_client)
    parsed = service.propose_method_edits(context=_context(), spec=_spec())

    assert call_count == 1
    assert parsed["decision"] == "no_fix"
    assert parsed["reason"] == "legacy"
