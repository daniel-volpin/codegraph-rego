"""Non-retrieval entry points must remain usable without the ML stack."""

import os
import subprocess
import sys

import pytest


@pytest.mark.parametrize(
    "module",
    [
        "codegraph.policy.integration",
        "codegraph.remediation.service",
        "api.routers.upload",
    ],
)
def test_import_without_retrieval_dependencies(module: str) -> None:
    program = """
import importlib
import sys

for dependency in ("faiss", "numpy", "sentence_transformers", "torch"):
    sys.modules[dependency] = None
importlib.import_module(sys.argv[1])
"""
    result = subprocess.run(
        [sys.executable, "-c", program, module],
        capture_output=True,
        text=True,
        timeout=20,
        env={**os.environ, "CODEGRAPH_ENV_FILE": "", "OTEL_SDK_DISABLED": "true"},
    )
    assert result.returncode == 0, result.stderr
