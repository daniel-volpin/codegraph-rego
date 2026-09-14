#!/usr/bin/env python3
"""Merge per-category agentic remediation runs into one combined report.

Each case belongs to exactly one category, so merging is a plain
concatenation of every group's results.jsonl -- unlike detection-eval
composition, there is no cross-category rule-firing overlap to reconcile.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from codegraph.evaluation.io import write_json  # noqa: E402
from codegraph.evaluation.remediation_runtime import build_agentic_outcome_summary  # noqa: E402

RESULTS_FILENAME = "results.jsonl"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("group_dirs", nargs="+", help="Per-category agentic run output directories to merge")
    parser.add_argument("--output-dir", required=True, help="Directory for the merged result set")
    return parser.parse_args()


def _load_results(group_dirs: list[Path]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for group_dir in group_dirs:
        path = group_dir / RESULTS_FILENAME
        if not path.is_file():
            raise SystemExit(f"{path} is missing. Re-run that group with --mode agentic.")
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                results.append(json.loads(line))
    return results


def main() -> int:
    args = parse_args()
    group_dirs = [Path(d) for d in args.group_dirs]
    results = _load_results(group_dirs)
    if not results:
        print("No results found across the given group directories.", file=sys.stderr)
        return 1

    outcomes = build_agentic_outcome_summary(results)
    output_dir = Path(args.output_dir)
    write_json(output_dir / "agentic_outcomes.json", outcomes)
    write_json(output_dir / "results.json", results)

    print(f"Merged {len(results)} cases from {len(group_dirs)} group(s).")
    print(json.dumps(outcomes, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
