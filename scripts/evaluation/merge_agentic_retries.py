#!/usr/bin/env python3
"""Upsert retried agentic remediation cases into a base result set."""

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

RESULTS_JSONL = "results.jsonl"
RESULTS_JSON = "results.json"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True, help="Base results file or directory containing results.json/results.jsonl")
    parser.add_argument("--retries", nargs="+", required=True, help="Retry result directories or json/jsonl files to overlay")
    parser.add_argument("--output-dir", required=True, help="Directory to save the updated result set and summary")
    return parser.parse_args()


def _load_case_list(source_path: Path) -> list[dict[str, Any]]:
    path = source_path
    if path.is_dir():
        if (path / RESULTS_JSONL).is_file():
            path = path / RESULTS_JSONL
        elif (path / RESULTS_JSON).is_file():
            path = path / RESULTS_JSON
        else:
            raise FileNotFoundError(f"No results.json or results.jsonl in {source_path}")

    if path.suffix == ".jsonl":
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return json.loads(path.read_text(encoding="utf-8"))


def _case_key(record: dict[str, Any]) -> str:
    """Derive consistent key for upsert matching by (testcase_id, rule/violation_id)."""
    case_id = str(record.get("case_id") or "")
    if case_id and "_" in case_id:
        parts = case_id.split("_")
        if len(parts) >= 2:
            return f"{parts[0]}_{parts[1]}"
    if "violation_id" in record and record["violation_id"]:
        return str(record["violation_id"])
    return str(record.get("testcase_id", ""))


def main() -> int:
    args = parse_args()
    base_cases = _load_case_list(Path(args.base))
    if not base_cases:
        print("Base result set is empty.", file=sys.stderr)
        return 1

    case_map: dict[str, dict[str, Any]] = {_case_key(c): c for c in base_cases}
    initial_count = len(case_map)
    initial_summary = build_agentic_outcome_summary(list(case_map.values()))

    updated_keys: set[str] = set()
    for retry_source in args.retries:
        retry_cases = _load_case_list(Path(retry_source))
        for case in retry_cases:
            key = _case_key(case)
            case_map[key] = case
            updated_keys.add(key)

    merged_cases = list(case_map.values())
    new_summary = build_agentic_outcome_summary(merged_cases)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    write_json(output_dir / "agentic_outcomes.json", new_summary)
    write_json(output_dir / "results.json", merged_cases)

    # Also write results.jsonl for downstream compatibility
    jsonl_path = output_dir / RESULTS_JSONL
    with jsonl_path.open("w", encoding="utf-8") as f:
        for case in merged_cases:
            f.write(json.dumps(case) + "\n")

    print(f"Base cases: {initial_count}")
    print(f"Overlayed/Updated cases: {len(updated_keys)}")
    print(f"Total merged cases: {len(merged_cases)}")
    print("\nInitial Summary:")
    print(json.dumps(initial_summary, indent=2))
    print("\nUpdated Summary:")
    print(json.dumps(new_summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
