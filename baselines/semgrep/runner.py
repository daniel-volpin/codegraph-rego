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


_REPO_ROOT = PACKAGE_DIR.parent.parent
_VENV_SEMGREP = _REPO_ROOT / ".venv" / "bin" / "semgrep"


def _resolve_semgrep_binary(explicit: str | None = None) -> str:
    """Return an executable semgrep path: explicit > PATH > project .venv."""

    if explicit:
        return explicit
    on_path = shutil.which("semgrep")
    if on_path:
        return on_path
    if _VENV_SEMGREP.is_file():
        return str(_VENV_SEMGREP)
    raise SemgrepNotInstalledError(
        "semgrep CLI not found. Install via "
        "`uv pip install --python .venv/bin/python semgrep`."
    )


def run_semgrep_baseline(
    target: Path,
    rules_dir: Path | None = DEFAULT_RULES_DIR,
    *,
    semgrep_binary: str | None = None,
    include_patterns: Iterable[str] = ("*.java",),
    extra_args: Iterable[str] = (),
    registry_config: str | None = None,
) -> SemgrepRunResult:
    """Run SemGrep on ``target``.

    Pass ``rules_dir`` to use a local rule directory (the default 8
    hand-written CodeGraph-mirror rules). Pass ``registry_config`` to
    use a SemGrep registry pack (e.g. ``"p/java"``, ``"p/owasp-top-ten"``)
    instead. Exactly one source must be provided; passing both is an
    error to keep the apples-to-apples comparison contract explicit.

    Registry mode requires network access; failures bubble up as a
    ``RuntimeError`` so callers can decide whether to skip the
    comparison.
    """

    binary = _resolve_semgrep_binary(semgrep_binary)
    target = target.resolve()

    if (rules_dir is None) == (registry_config is None):
        raise ValueError(
            "run_semgrep_baseline: pass exactly one of rules_dir or registry_config"
        )

    if not target.exists():
        raise FileNotFoundError(f"SemGrep target does not exist: {target}")

    if rules_dir is not None:
        rules_dir = rules_dir.resolve()
        if not rules_dir.exists():
            raise FileNotFoundError(
                f"SemGrep rules directory does not exist: {rules_dir}"
            )
        config_value = str(rules_dir)
    else:
        config_value = registry_config

    cmd: list[str] = [
        binary,
        "scan",
        "--config",
        config_value,
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

    # cwd is anchored to the repo root so SemGrep discovers the
    # project-local .semgrepignore regardless of who invoked the runner.
    # Without this, a caller running from /tmp or any non-repo directory
    # would silently fall back to SemGrep's default semgrepignore template
    # (which excludes tests/) and skip the LexicalNoiseJava fixtures.
    completed = subprocess.run(
        cmd,
        check=False,
        capture_output=True,
        text=True,
        cwd=str(_REPO_ROOT),
    )
    if completed.returncode not in (0, 1):
        raise RuntimeError(
            f"semgrep failed (exit {completed.returncode}): {completed.stderr.strip()[:500]}"
        )

    payload = json.loads(completed.stdout or "{}")
    findings = tuple(_parse_finding(item) for item in payload.get("results", []))
    return SemgrepRunResult(
        findings=findings,
        rules_path=rules_dir if rules_dir is not None else Path(config_value),
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
