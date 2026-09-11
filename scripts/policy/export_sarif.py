#!/usr/bin/env python3
"""CLI utility to export CodeGraph policy evaluation findings to standard SARIF 2.1.0."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from codegraph.policy.service import export_sarif


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Export CodeGraph policy violations to OASIS SARIF v2.1.0.")
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        help="Path to write SARIF JSON output (default: stdout)",
    )
    parser.add_argument(
        "--workspace-root",
        type=str,
        default=None,
        help="Workspace root directory to evaluate (default: configured upload dir)",
    )
    parser.add_argument(
        "--rule-id",
        action="append",
        dest="rule_ids",
        default=None,
        help="Filter findings to specific rule ID(s) (can be repeated)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    sarif_doc = export_sarif(workspace_root=args.workspace_root, rule_ids=args.rule_ids)

    formatted = json.dumps(sarif_doc, indent=2)
    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(formatted, encoding="utf-8")
        print(f"SARIF report written to {out_path}", file=sys.stderr)
    else:
        print(formatted)
    return 0


if __name__ == "__main__":
    sys.exit(main())
