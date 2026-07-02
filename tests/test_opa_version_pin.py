"""Guard: every environment must install the same pinned OPA version.

OPA's policy semantics can change between versions, so benchmark numbers are only
reproducible if the container, the venv setup script, and CI all install the same
engine. The canonical thesis_final_* provenance records OPA 1.15.1, so all three
must pin v1.15.1. This test fails on drift or any reversion to the unpinned
'latest' channel.
"""

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]

# Version recorded in the canonical thesis_final_* provenance manifests.
CANONICAL_OPA_VERSION = "v1.15.1"


def _read(path: str) -> str:
    return (_ROOT / path).read_text(encoding="utf-8")


def test_all_environments_pin_same_canonical_opa_version() -> None:
    dockerfile = _read("Dockerfile.backend")
    setup = _read("scripts/setup_benchmark_env.sh")
    ci = _read(".github/workflows/ci.yml")
    readme = _read("README.md")
    repro = _read("REPRODUCIBILITY.md")

    docker_match = re.search(r"OPA_VERSION=(v\d+\.\d+\.\d+)", dockerfile)
    setup_match = re.search(r"/releases/download/(v\d+\.\d+\.\d+)/", setup)
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
    assert versions == {CANONICAL_OPA_VERSION}, (
        f"OPA version drift across environments: {sorted(versions)}; all must pin "
        f"{CANONICAL_OPA_VERSION} (the canonical-evidence version)"
    )


def test_no_environment_uses_latest_opa() -> None:
    for path in ("Dockerfile.backend", ".github/workflows/ci.yml"):
        assert "downloads/latest/opa" not in _read(path), (
            f"{path} must not download OPA from the unpinned 'latest' channel"
        )
