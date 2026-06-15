"""Tripwire protecting canonical thesis artifacts from silent change.

The thesis-final evaluation artifacts under ``outputs/thesis_final_*`` are
tracked in git and cited in the thesis. Eval scripts write into ``--output-dir``
unconditionally, so a stray run pointed at a canonical directory would silently
overwrite the oracle. This test recomputes each hash recorded in
``outputs/canonical_manifest.sha256`` and fails if any canonical file changed,
was removed, or was added without regenerating the manifest.

A legitimate, deliberate regeneration updates the manifest via
``scripts/evaluation/generate_canonical_manifest.py`` in the same commit.
"""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = _ROOT / "outputs" / "canonical_manifest.sha256"
CANONICAL_GLOB = "outputs/thesis_final_*"


def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_manifest() -> dict[str, str]:
    entries: dict[str, str] = {}
    for line in MANIFEST_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        digest, _, rel = line.partition("  ")
        entries[rel] = digest
    return entries


def _tracked_canonical_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", CANONICAL_GLOB],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return sorted(line for line in out.stdout.splitlines() if line.strip())


def test_manifest_exists() -> None:
    assert MANIFEST_PATH.is_file(), "outputs/canonical_manifest.sha256 is missing"


def test_canonical_artifacts_match_manifest() -> None:
    manifest = _load_manifest()
    mismatches: list[str] = []
    for rel, expected in manifest.items():
        path = _ROOT / rel
        if not path.is_file():
            mismatches.append(f"missing: {rel}")
            continue
        actual = _file_sha256(path)
        if actual != expected:
            mismatches.append(f"changed: {rel}")
    assert not mismatches, (
        "Canonical artifact(s) differ from the recorded manifest. If this change "
        "is intentional, regenerate via scripts/evaluation/generate_canonical_manifest.py "
        "and commit both together.\n  " + "\n  ".join(mismatches)
    )


def test_manifest_covers_all_tracked_canonical_files() -> None:
    manifest = _load_manifest()
    tracked = set(_tracked_canonical_files())
    untracked_in_manifest = tracked - set(manifest)
    assert not untracked_in_manifest, (
        "Tracked canonical files are not in the manifest (regenerate it):\n  "
        + "\n  ".join(sorted(untracked_in_manifest))
    )
    stale = set(manifest) - tracked
    assert not stale, (
        "Manifest references files no longer tracked (regenerate it):\n  " + "\n  ".join(sorted(stale))
    )


if __name__ == "__main__":
    pytest.main([__file__])
