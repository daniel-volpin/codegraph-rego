"""Shared pytest configuration for policy tests.

Detection tests that shell out to the real ``opa`` binary are marked
``requires_opa``. When the binary is absent (e.g. a local dev box without OPA
installed) those tests are skipped with a clear reason instead of failing with
an opaque ``FileNotFoundError`` from ``subprocess``. CI installs OPA, so they
still run there.
"""

import shutil

import pytest

_OPA_AVAILABLE = shutil.which("opa") is not None


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "requires_opa: test invokes the real OPA binary; skipped when 'opa' is not on PATH.",
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if _OPA_AVAILABLE:
        return
    skip = pytest.mark.skip(reason="opa binary not found on PATH; install OPA to run detection tests")
    for item in items:
        if item.get_closest_marker("requires_opa") is not None:
            item.add_marker(skip)
