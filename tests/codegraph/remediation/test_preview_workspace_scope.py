"""A preview miss must say which workspace root it searched.

Policy re-evaluation inside remediation is scoped to a workspace root. With no
``file_path`` that root falls back to the upload workspace, so a violation in a
workspace ingested anywhere else — a CLI ingest, a benchmark run — is invisible
and the caller used to get a flat "Violation X not found". That reads as "the
finding is gone", when the finding is simply outside the scope that was searched.
"""

from __future__ import annotations

from typing import Any

import pytest

from codegraph.remediation.service import RemediationService


@pytest.fixture
def service(monkeypatch: pytest.MonkeyPatch) -> RemediationService:
    svc = RemediationService()
    monkeypatch.setattr(
        RemediationService,
        "get_violation_context",
        lambda *_args, **_kwargs: None,
    )
    return svc


def test_not_found_names_the_searched_workspace_root(service: RemediationService) -> None:
    result: dict[str, Any] = service.preview_virtual_fix(
        "ISO-A.10-WEAK-HASH",
        method_key="ws@rev:Foo.java#method:doPost/0/",
    )

    assert result["status"] == "NOT_FOUND"
    searched = result["workspace_root"]
    assert searched, "the searched root must be reported"
    assert searched in result["error"], "the error text must name the root that was searched"
    assert "file_path" in result["hint"], "the hint must point at the parameter that fixes it"


def test_missing_method_key_still_reports_invalid(service: RemediationService) -> None:
    result = service.preview_virtual_fix("ISO-A.10-WEAK-HASH", method_key="")

    assert result["status"] == "INVALID"
    assert "method_key" in result["error"]
