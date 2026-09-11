"""Guard: every environment must install the same pinned OPA version.

OPA's policy semantics can change between versions, so benchmark numbers are only
reproducible if the container, the venv setup script, and CI all install the same
engine. Historical thesis evidence retains its recorded engine; the current
source baseline must agree across supported environments.
"""

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]

CURRENT_OPA_VERSION = "v1.20.2"


def _read(path: str) -> str:
    return (_ROOT / path).read_text(encoding="utf-8")


def test_all_environments_pin_same_canonical_opa_version() -> None:
    dockerfile = _read("Dockerfile.backend")
    setup = _read("scripts/setup_benchmark_env.sh")
    ci = _read(".github/workflows/ci.yml")
    readme = _read("README.md")
    repro = _read("REPRODUCIBILITY.md")

    docker_match = re.search(r"OPA_VERSION=(v\d+\.\d+\.\d+)", dockerfile)
    setup_match = re.search(r"OPA_VERSION=(v\d+\.\d+\.\d+)", setup)
    ci_match = re.search(r"OPA_VERSION:\s*(v\d+\.\d+\.\d+)", ci)
    readme_match = re.search(r"OPA `(v\d+\.\d+\.\d+)`", readme)
    repro_match = re.search(r"OPA `(v\d+\.\d+\.\d+)`", repro)

    assert docker_match, "Dockerfile.backend must pin OPA via OPA_VERSION=vX.Y.Z"
    assert setup_match, "setup_benchmark_env.sh must download a pinned OPA release"
    assert ci_match, "ci.yml must pin OPA via OPA_VERSION: vX.Y.Z"
    assert readme_match, "README.md must specify pinned OPA version vX.Y.Z"
    assert repro_match, "REPRODUCIBILITY.md must specify pinned OPA version vX.Y.Z"

    versions = {
        docker_match.group(1),
        setup_match.group(1),
        ci_match.group(1),
        readme_match.group(1),
        repro_match.group(1),
    }
    assert versions == {CURRENT_OPA_VERSION}, (
        f"OPA version drift across environments: {sorted(versions)}; all must pin "
        f"{CURRENT_OPA_VERSION} (the current source baseline)"
    )


def test_no_environment_uses_latest_opa() -> None:
    for path in ("Dockerfile.backend", ".github/workflows/ci.yml"):
        assert "downloads/latest/opa" not in _read(path), (
            f"{path} must not download OPA from the unpinned 'latest' channel"
        )


def test_backend_image_copies_runtime_policy_assets() -> None:
    dockerfile = _read("Dockerfile.backend")
    assert re.search(r"^COPY policy\s+\./policy\s*$", dockerfile, flags=re.MULTILINE), (
        "Dockerfile.backend must copy top-level policy/ into the runtime image so OPA can load Rego modules"
    )
    assert re.search(r"^COPY configs\s+\./configs\s*$", dockerfile, flags=re.MULTILINE), (
        "Dockerfile.backend must copy configs/ into the runtime image for policy registry lookups"
    )


def test_python_support_floor_is_consistent_with_packaging_and_docs() -> None:
    pyproject = _read("pyproject.toml")
    lockfile = _read("uv.lock")
    ci = _read(".github/workflows/ci.yml")
    dockerfile = _read("Dockerfile.backend")
    readme = _read("README.md")
    repro = _read("REPRODUCIBILITY.md")

    requires_python = re.search(r'^requires-python = "([^"]+)"', pyproject, flags=re.MULTILINE)
    lock_requires_python = re.search(r'^requires-python = "([^"]+)"', lockfile, flags=re.MULTILINE)
    ci_python = re.search(r'python-version:\s*"([^"]+)"', ci)
    docker_python = re.search(
        r"^FROM python:(\d+\.\d+\.\d+)-slim(?:-[a-z0-9]+)?(?:@sha256:[a-f0-9]+)?$",
        dockerfile,
        flags=re.MULTILINE,
    )

    assert requires_python, "pyproject.toml must declare requires-python"
    assert lock_requires_python, "uv.lock must declare requires-python"
    assert ci_python, "CI backend job must pin python-version"
    assert requires_python.group(1) == ">=3.14"
    assert lock_requires_python.group(1) == ">=3.14"
    assert docker_python, "Dockerfile.backend must pin the current Python maintenance release"
    assert "Python 3.14+" in readme, "README.md prerequisites must match the supported Python floor"
    assert "Python 3.14+" in repro, "REPRODUCIBILITY.md prerequisites must match the supported Python floor"
    assert ci_python.group(1) == docker_python.group(1) == _read(".python-version").strip() == "3.14.7"
