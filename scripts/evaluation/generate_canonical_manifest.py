#!/usr/bin/env python3
"""Regenerate the canonical-artifact checksum manifest.

The thesis-final evaluation artifacts under ``outputs/thesis_final_*`` are
intentionally tracked in git (see ``docs/architecture/artifact-policy.md``) but
nothing previously stopped a stray ``--output-dir`` from silently overwriting
them. ``tests/test_canonical_artifacts.py`` recomputes the hashes recorded here
and fails if any canonical file changed without an explicit manifest update.

Run this **only** when a canonical metric change is intentional and justified:

    python scripts/evaluation/generate_canonical_manifest.py

Then commit both the regenerated artifacts and the updated manifest in the same
commit, with a message explaining the deliberate regeneration.
"""

from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = _ROOT / "outputs" / "canonical_manifest.sha256"
CANONICAL_GLOB = "outputs/thesis_final_*"


def tracked_canonical_files() -> list[str]:
    """git-tracked paths under the canonical output directories, sorted."""
    out = subprocess.run(
        ["git", "ls-files", CANONICAL_GLOB],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return sorted(line for line in out.stdout.splitlines() if line.strip())


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def build_manifest_lines() -> list[str]:
    lines = []
    for rel in tracked_canonical_files():
        digest = file_sha256(_ROOT / rel)
        lines.append(f"{digest}  {rel}")
    return lines


def main() -> int:
    lines = build_manifest_lines()
    MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    MANIFEST_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {len(lines)} entries to {MANIFEST_PATH.relative_to(_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
