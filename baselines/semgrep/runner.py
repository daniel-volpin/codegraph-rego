"""Run SemGrep against a fixture tree and parse the JSON output.

This is a thin wrapper around the ``semgrep`` CLI. It loads our 8
hand-written rules (mirrors of the 8 active CodeGraph CWE families)
and produces a typed report that downstream tests and evaluators can
compare against CodeGraph results.

The wrapper is intentionally minimal: no rule discovery, no caching,
no parallel orchestration. SemGrep already handles those.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


PACKAGE_DIR = Path(__file__).resolve().parent
DEFAULT_RULES_DIR = PACKAGE_DIR / "rules"


@dataclass(frozen=True)
class SemgrepFinding:
    """One SemGrep match — rule, file, span, message."""

    rule_id: str
    file_path: str
    start_line: int
    end_line: int
    message: str

    @property
    def codegraph_violation_id(self) -> str | None:
        """Return the CodeGraph violation_id this rule maps to, or None.

        SemGrep rule ids are written to mirror CodeGraph IDs:
        ``iso-a10-weak-hash`` -> ``ISO-A.10-WEAK-HASH`` (note the dot
        between ``A`` and the control number). The mapping is
        deterministic and lossless.
        """

        bare = self.rule_id.rsplit(".", 1)[-1]
        parts = bare.split("-")
        if len(parts) < 3 or parts[0].lower() != "iso":
            return None
        control = parts[1]
        if not (control.startswith(("a", "A")) and control[1:].isdigit()):
            return None
        control_norm = f"A.{control[1:]}"
        tail = "-".join(p.upper() for p in parts[2:])
        return f"ISO-{control_norm}-{tail}"


@dataclass(frozen=True)
class SemgrepRunResult:
    """Aggregated result of one SemGrep invocation."""

    findings: tuple[SemgrepFinding, ...]
    rules_path: Path
    target: Path
    raw: dict = field(default_factory=dict)

    def findings_by_file(self) -> dict[str, tuple[SemgrepFinding, ...]]:
        bucket: dict[str, list[SemgrepFinding]] = {}
        for f in self.findings:
            bucket.setdefault(f.file_path, []).append(f)
        return {k: tuple(v) for k, v in bucket.items()}

    def findings_by_rule(self) -> dict[str, tuple[SemgrepFinding, ...]]:
        bucket: dict[str, list[SemgrepFinding]] = {}
        for f in self.findings:
            bucket.setdefault(f.rule_id, []).append(f)
        return {k: tuple(v) for k, v in bucket.items()}


class SemgrepNotInstalledError(RuntimeError):
    """Raised when the ``semgrep`` CLI is not on PATH or in the venv."""


def _resolve_semgrep_binary(explicit: str | None = None) -> str:
    if explicit:
        return explicit
    for candidate in ("semgrep", str(PACKAGE_DIR.parent.parent / ".venv" / "bin" / "semgrep")):
        resolved = shutil.which(candidate) or (candidate if Path(candidate).is_file() else None)
        if resolved:
            return resolved
    raise SemgrepNotInstalledError(
        "semgrep CLI not found. Install via `uv pip install --python .venv/bin/python semgrep`."
    )


def run_semgrep_baseline(
    target: Path,
    rules_dir: Path = DEFAULT_RULES_DIR,
    *,
    semgrep_binary: str | None = None,
    include_patterns: Iterable[str] = ("*.java",),
    extra_args: Iterable[str] = (),
) -> SemgrepRunResult:
    """Run SemGrep on ``target`` using the rules under ``rules_dir``."""

    binary = _resolve_semgrep_binary(semgrep_binary)
    target = target.resolve()
    rules_dir = rules_dir.resolve()

    if not target.exists():
        raise FileNotFoundError(f"SemGrep target does not exist: {target}")
    if not rules_dir.exists():
        raise FileNotFoundError(f"SemGrep rules directory does not exist: {rules_dir}")

    cmd: list[str] = [
        binary,
        "scan",
        "--config",
        str(rules_dir),
        "--json",
        "--quiet",
        "--metrics=off",
        "--disable-version-check",
        "--no-git-ignore",
    ]
    for pattern in include_patterns:
        cmd.extend(["--include", pattern])
    cmd.extend(extra_args)
    cmd.append(str(target))

    completed = subprocess.run(
        cmd,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode not in (0, 1):
        raise RuntimeError(
            f"semgrep failed (exit {completed.returncode}): {completed.stderr.strip()[:500]}"
        )

    payload = json.loads(completed.stdout or "{}")
    findings = tuple(_parse_finding(item) for item in payload.get("results", []))
    return SemgrepRunResult(
        findings=findings,
        rules_path=rules_dir,
        target=target,
        raw=payload,
    )


def _parse_finding(item: dict) -> SemgrepFinding:
    start = item.get("start", {})
    end = item.get("end", {})
    extra = item.get("extra", {})
    return SemgrepFinding(
        rule_id=str(item.get("check_id", "")),
        file_path=str(item.get("path", "")),
        start_line=int(start.get("line", 0) or 0),
        end_line=int(end.get("line", 0) or 0),
        message=str(extra.get("message", "")),
    )
