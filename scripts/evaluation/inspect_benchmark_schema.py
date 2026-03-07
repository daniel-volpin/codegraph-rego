"""
Inspect the OWASP Benchmark ground truth schema.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from codegraph.evaluation.benchmark import find_ground_truth_file, inspect_ground_truth_schema, load_selection_config


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Inspect OWASP Benchmark ground truth schema.")
    parser.add_argument(
        "--config",
        default="configs/benchmark_selection.json",
        help="Benchmark selection config JSON (default: %(default)s)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Optional path to write schema JSON",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = Path(__file__).resolve().parents[2]
    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = (repo_root / config_path).resolve()

    selection_cfg = load_selection_config(config_path)
    benchmark_root = Path(selection_cfg["benchmark_root"])
    truth_path = find_ground_truth_file(benchmark_root, selection_cfg.get("ground_truth_path"))
    schema = inspect_ground_truth_schema(truth_path)
    schema["ground_truth_file"] = truth_path.as_posix()
    payload = json.dumps(schema, indent=2)
    print(payload)
    if args.output:
        output_path = Path(args.output)
        if not output_path.is_absolute():
            output_path = (repo_root / output_path).resolve()
        output_path.write_text(payload, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
