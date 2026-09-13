"""Every script under ``scripts/`` must be runnable by path, from any directory.

This repository is a virtual uv project: ``codegraph`` is not installed into the
environment, so ``import codegraph`` only resolves when the repository root is on
``sys.path``. A script at the repository root got that for free, because
``sys.path[0]`` is the script's own directory. A script under ``scripts/<area>/``
does not, and must insert the root itself.

Moving the evaluation runners from the root into ``scripts/evaluation/`` broke
every documented command in REPRODUCIBILITY.md without failing a single test,
because the tests that load those modules do so through ``importlib`` from a
process that already has the root on ``sys.path``. This test closes that gap by
executing each script the way an operator does.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = REPO_ROOT / "scripts"


def _scripts_importing_codegraph() -> list[Path]:
    found: list[Path] = []
    for path in sorted(SCRIPTS_DIR.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if "from codegraph" in text or "import codegraph" in text:
            found.append(path)
    return found


SCRIPTS = _scripts_importing_codegraph()


def test_scripts_were_discovered() -> None:
    """Guard the guard: an empty list would make the test below vacuously pass."""
    assert SCRIPTS, f"no scripts importing codegraph found under {SCRIPTS_DIR}"


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.relative_to(REPO_ROOT).as_posix())
def test_script_imports_codegraph_from_any_cwd(script: Path, tmp_path: Path) -> None:
    """``--help`` exercises module import without touching Neo4j, OPA or a model."""
    proc = subprocess.run(
        [sys.executable, str(script), "--help"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=120,
    )
    combined = f"{proc.stdout}\n{proc.stderr}"
    assert "ModuleNotFoundError: No module named 'codegraph'" not in combined, (
        f"{script.relative_to(REPO_ROOT)} cannot import codegraph when run by path. "
        "Scripts under scripts/ must insert REPO_ROOT into sys.path before importing codegraph."
    )
