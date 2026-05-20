"""CLI entry point: ``python -m baselines.semgrep --target <dir> --out <file>``.

Runs the 8 hand-written CodeGraph-mirror SemGrep rules against ``target``
and writes a typed JSON report to ``out``. Designed to be invoked from
the comparative-eval scripts that produce the thesis Phase D tables.

Exit codes:
    0  — scan completed (findings allowed, no internal error).
    2  — fixture root or rules dir missing.
    3  — semgrep CLI not installed.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from baselines.semgrep.runner import (
    DEFAULT_RULES_DIR,
    SemgrepNotInstalledError,
    run_semgrep_baseline,
)


def _build_argparser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m baselines.semgrep",
        description="Run the 8 CodeGraph-mirror SemGrep rules against a fixture tree.",
    )
    parser.add_argument(
        "--target",
        required=True,
        type=Path,
        help="Directory tree to scan (e.g. tests/fixtures/lexical_noise_v1).",
    )
    parser.add_argument(
        "--rules-dir",
        type=Path,
        default=DEFAULT_RULES_DIR,
        help="Directory containing the SemGrep rule YAMLs (default: bundled rules/).",
    )
    parser.add_argument(
        "--out",
        type=Path,
        required=True,
        help="Path to write the JSON report.",
    )
    parser.add_argument(
        "--include",
        action="append",
        default=None,
        help="File-glob to include. Repeat for multiple. Default: *.java",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_argparser()
    args = parser.parse_args(argv)

    if not args.target.exists():
        print(f"error: target does not exist: {args.target}", file=sys.stderr)
        return 2
    if not args.rules_dir.exists():
        print(f"error: rules-dir does not exist: {args.rules_dir}", file=sys.stderr)
        return 2

    try:
        result = run_semgrep_baseline(
            target=args.target,
            rules_dir=args.rules_dir,
            include_patterns=tuple(args.include) if args.include else ("*.java",),
        )
    except SemgrepNotInstalledError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3

    payload = {
        "target": str(result.target),
        "rules_path": str(result.rules_path),
        "files_scanned": len(result.raw.get("paths", {}).get("scanned", [])),
        "finding_count": len(result.findings),
        "findings": [
            {
                "rule_id": f.rule_id,
                "codegraph_violation_id": f.codegraph_violation_id,
                "file_path": f.file_path,
                "start_line": f.start_line,
                "end_line": f.end_line,
                "message": f.message,
            }
            for f in result.findings
        ],
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
    print(f"wrote {args.out}  files_scanned={payload['files_scanned']}  findings={payload['finding_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
