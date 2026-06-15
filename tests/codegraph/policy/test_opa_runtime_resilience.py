"""Resilience regression tests for the OPA subprocess boundary."""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock

import pytest

from codegraph.policy.runtime import opa as runtime_opa

Bundle = dict[str, Any]
Evaluator = Callable[[Bundle], Any]


class CompletedOpaProcess:
    returncode = 0
    stdout = '{"result": []}'
    stderr = ""


@pytest.fixture
def bundle() -> Bundle:
    return {"target_method": "com.example.Foo.bar()", "source_code": ""}


@pytest.mark.parametrize(
    "evaluator",
    [
        runtime_opa.evaluate_bundle,
        runtime_opa.evaluate_package_root,
    ],
)
def test_opa_timeout_is_reported_as_runtime_error(
    monkeypatch: pytest.MonkeyPatch,
    bundle: Bundle,
    evaluator: Evaluator,
) -> None:
    def raise_timeout(*_args: Any, **_kwargs: Any) -> None:
        raise subprocess.TimeoutExpired(cmd="opa", timeout=120)

    monkeypatch.setattr(runtime_opa.subprocess, "run", raise_timeout)

    with pytest.raises(RuntimeError, match="timed out"):
        evaluator(bundle)


def test_evaluate_bundle_passes_timeout_to_subprocess(
    monkeypatch: pytest.MonkeyPatch,
    bundle: Bundle,
) -> None:
    run = Mock(return_value=CompletedOpaProcess())
    monkeypatch.setattr(runtime_opa.subprocess, "run", run)

    runtime_opa.evaluate_bundle(bundle)

    assert run.call_args is not None
    assert run.call_args.kwargs["timeout"] > 0


def test_timeout_seconds_comes_from_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runtime_opa, "settings", SimpleNamespace(opa_timeout_seconds=7.5))

    assert runtime_opa._opa_timeout_seconds() == 7.5
