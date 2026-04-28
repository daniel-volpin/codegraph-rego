from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from codegraph.evaluation.remediation_runtime import (  # noqa: E402
    build_confidence_calibration,
    render_calibration_markdown,
)


def _load_results_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8").splitlines():
        text = line.strip()
        if not text:
            continue
        rows.append(json.loads(text))
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Generate confidence calibration metrics (Brier, ECE, reliability bins) from remediation results.jsonl"
        )
    )
    parser.add_argument(
        "--run-dir",
        required=True,
        help="Run directory containing results.jsonl (for example outputs/<run-name>)",
    )
    parser.add_argument(
        "--bins",
        type=int,
        default=10,
        help="Number of reliability bins (default: 10)",
    )
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    results_path = run_dir / "results.jsonl"
    rows = _load_results_jsonl(results_path)
    calibration = build_confidence_calibration(rows, bins=max(1, args.bins))

    if calibration is None:
        print(
            "No confidence scores found in results.jsonl; nothing to write. "
            "Expected per-case confidence.score under the confidence object."
        )
        return 0

    out_path = run_dir / "remediation_calibration.json"
    out_path.write_text(json.dumps(calibration, indent=2), encoding="utf-8")
    md_path = run_dir / "remediation_calibration.md"
    md_path.write_text(render_calibration_markdown(calibration), encoding="utf-8")
    print(f"Wrote {out_path}")
    print(f"Wrote {md_path}")
    print(f"Brier={calibration.get('brier_score')} ECE={calibration.get('ece')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
