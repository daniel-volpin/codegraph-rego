"""Guard: the container and the venv setup script must pin the same OPA version.

OPA's policy semantics can change between versions, so benchmark numbers are only
reproducible if every environment installs the same engine. This test fails if the
Dockerfile and setup script drift apart (or if either reverts to 'latest').
"""

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]


def _read(path: str) -> str:
    return (_ROOT / path).read_text(encoding="utf-8")


def test_dockerfile_pins_opa_version_matching_setup_script() -> None:
    dockerfile = _read("Dockerfile.backend")
    setup = _read("scripts/setup_benchmark_env.sh")

    docker_match = re.search(r"OPA_VERSION=(v\d+\.\d+\.\d+)", dockerfile)
    setup_match = re.search(r"/releases/download/(v\d+\.\d+\.\d+)/", setup)

    assert docker_match, "Dockerfile.backend must pin OPA via OPA_VERSION=vX.Y.Z"
    assert setup_match, "setup_benchmark_env.sh must download a pinned OPA release"
    assert docker_match.group(1) == setup_match.group(1), (
        f"OPA version drift: Dockerfile pins {docker_match.group(1)} but setup script "
        f"pins {setup_match.group(1)}"
    )


def test_dockerfile_does_not_use_latest_opa() -> None:
    dockerfile = _read("Dockerfile.backend")
    assert "downloads/latest/opa" not in dockerfile, (
        "Dockerfile.backend must not download OPA from the unpinned 'latest' channel"
    )
