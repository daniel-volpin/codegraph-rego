from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts/setup_benchmark_env.sh"
OPA_BINARY = b'#!/bin/sh\nprintf "Version: 1.20.2\\n"\n'
OLD_OPA = b'#!/bin/sh\nprintf "Version: 1.15.1\\n"\n'


@pytest.fixture
def setup_workspace(tmp_path):
    commands = tmp_path / "commands"
    commands.mkdir()

    def executable(name, body):
        path = commands / name
        path.write_text(f"#!{sys.executable}\n{body}", encoding="utf-8")
        path.chmod(0o755)

    for name in ("java", "javac", "mvn", "make"):
        executable(name, "pass\n")
    executable(
        "uv",
        "from pathlib import Path\nimport sys\n"
        "assert sys.argv[1] == 'sync'\n"
        "path = Path('.venv/bin/python')\npath.parent.mkdir(parents=True, exist_ok=True)\n"
        "path.symlink_to(sys.executable)\n",
    )
    executable(
        "uname",
        "import os, sys\nprint(os.environ.get('TEST_OS', 'Linux') if sys.argv[1] == '-s' else 'x86_64')\n",
    )
    executable(
        "curl",
        "import hashlib, os, sys\nfrom pathlib import Path\n"
        "args = sys.argv[1:]\nurl = args[-1]\n"
        "if os.environ.get('FAIL_DOWNLOAD') or 'darwin_amd64_static' in url: sys.exit(22)\n"
        "target = Path(args[args.index('-o') + 1])\n"
        f"binary = {OPA_BINARY!r}\n"
        "if url.endswith('.sha256'):\n"
        "    digest = '0' * 64 if os.environ.get('BAD_CHECKSUM') else hashlib.sha256(binary).hexdigest()\n"
        "    target.write_text(digest + '\\n')\n"
        "else:\n    target.write_bytes(binary)\n",
    )
    opa = tmp_path / ".venv/bin/opa"
    opa.parent.mkdir(parents=True)
    opa.write_bytes(OLD_OPA)
    opa.chmod(0o755)
    env = dict(os.environ, PATH=f"{commands}:{os.environ['PATH']}")
    return tmp_path, opa, env


def _run(workspace, env):
    return subprocess.run(["bash", str(SCRIPT)], cwd=workspace, env=env, capture_output=True, text=True, timeout=15)


def test_setup_replaces_outdated_cached_opa(setup_workspace):
    root, opa, env = setup_workspace
    result = _run(root, env)
    assert result.returncode == 0, result.stdout + result.stderr
    assert opa.read_bytes() == OPA_BINARY


@pytest.mark.parametrize("failure", ["FAIL_DOWNLOAD", "BAD_CHECKSUM"])
def test_failed_opa_upgrade_keeps_cached_binary_but_refuses_success(setup_workspace, failure):
    root, opa, env = setup_workspace
    result = _run(root, env | {failure: "1"})
    assert result.returncode != 0
    assert opa.read_bytes() == OLD_OPA


def test_setup_uses_available_macos_intel_release_asset(setup_workspace):
    root, opa, env = setup_workspace
    result = _run(root, env | {"TEST_OS": "Darwin"})
    assert result.returncode == 0, result.stdout + result.stderr
    assert opa.read_bytes() == OPA_BINARY
