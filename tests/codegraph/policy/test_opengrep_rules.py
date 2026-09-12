"""Contract tests for the OpenGrep taint rules.

Each rule file under ``policy/opengrep/`` is paired with an annotated Java
fixture of the same basename under ``tests/fixtures/opengrep/``. The fixture
marks expected findings with ``ruleid:`` and expected non-findings with
``ok:``, and OpenGrep's own test runner enforces both directions, so a rule
that stops detecting a real sink — or starts firing on a safe shape — fails
here rather than silently in a benchmark run.

Adding a rule requires no change to this file: drop the rule YAML and a
matching fixture and it is picked up automatically.
"""

from __future__ import annotations

import shutil
import subprocess

import pytest

from codegraph.policy.opengrep_bridge import discover_rule_files
from tests._support import PROJECT_ROOT

_FIXTURE_DIR = PROJECT_ROOT / "tests" / "fixtures" / "opengrep"
_OPENGREP_AVAILABLE = shutil.which("opengrep") is not None

_RULE_FILES = discover_rule_files()


def test_every_rule_file_has_a_fixture() -> None:
    """A rule without a fixture is untested; fail loudly instead of skipping."""
    assert _RULE_FILES, "no OpenGrep rule files discovered"
    missing = [path.name for path in _RULE_FILES if not (_FIXTURE_DIR / f"{path.stem}.java").is_file()]
    assert not missing, f"OpenGrep rules without a test fixture: {missing}"


@pytest.mark.skipif(not _OPENGREP_AVAILABLE, reason="opengrep not installed")
@pytest.mark.parametrize("rule_path", _RULE_FILES, ids=lambda p: p.stem)
def test_rule_matches_annotated_fixture(rule_path) -> None:
    fixture = _FIXTURE_DIR / f"{rule_path.stem}.java"
    result = subprocess.run(
        ["opengrep", "test", "--config", str(rule_path), str(fixture)],
        capture_output=True,
        text=True,
        timeout=180,
        cwd=PROJECT_ROOT,
    )
    combined = f"{result.stdout}\n{result.stderr}"
    assert "All tests passed" in combined, f"{rule_path.stem} rule contract failed:\n{combined}"
