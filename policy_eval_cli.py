"""
CLI wrapper to run ISO 27001 policy evaluation (with optional pretty JSON output).
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List


def parse_args(argv: List[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate ISO 27001 policies via OPA.")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print full JSON response (default is a compact summary)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Only display the first N violations when not using --json",
    )
    parser.add_argument(
        "--max-bundles",
        type=int,
        default=None,
        help="Only scan the first N method bundles (early stop)",
    )
    parser.add_argument(
        "--max-total-violations",
        type=int,
        default=None,
        help="Stop after collecting N violations total (early stop)",
    )
    parser.add_argument(
        "--max-per-violation-id",
        type=int,
        default=None,
        help="Cap how many times a single violation_id can appear",
    )
    return parser.parse_args(argv)


def _print_summary(result: dict, limit: int | None) -> None:
    violations = result.get("violations") or []
    total = len(violations)
    shown = violations if limit is None else violations[:limit]
    print(f"Found {total} violation(s).")
    for idx, violation in enumerate(shown, start=1):
        ident = violation.get("violation_id") or violation.get("id")
        method = violation.get("target_method") or violation.get("method")
        reason = violation.get("reason")
        print(f"[{idx}] {ident} :: {method}")
        if reason:
            print(f"    {reason}")


def main(argv: List[str] | None = None) -> int:
    args = parse_args(argv)
    from codegraph.policy import integration as policy_integration

    result = policy_integration.evaluate_policies(
        max_bundles=args.max_bundles,
        max_total_violations=args.max_total_violations,
        max_per_violation_id=args.max_per_violation_id,
    )
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        if "error" in result:
            print(json.dumps(result, indent=2))
            return 1
        _print_summary(result, args.limit)
    return 0


if __name__ == "__main__":
    sys.exit(main())
