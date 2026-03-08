from __future__ import annotations

import argparse
from pathlib import Path

from reporting_helpers import (
    DEFAULT_OUTPUT_DIR,
    DEFAULT_RUN_SPECS,
    build_report,
    parse_run_arg,
    write_report,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Summarize benchmark outputs into reusable report artifacts.")
    parser.add_argument(
        "--outputs-root",
        default="outputs",
        help="Directory containing benchmark output folders (default: %(default)s).",
    )
    parser.add_argument(
        "--output-dir",
        default=DEFAULT_OUTPUT_DIR,
        help="Directory where report.json and report.md will be written (default: %(default)s).",
    )
    parser.add_argument(
        "--run",
        action="append",
        default=[],
        metavar="RUN_ID|STAGE|PATH|LABEL|COMPARE_TO",
        help=(
            "Optional run spec. PATH may be relative to --outputs-root or absolute. "
            "When omitted, the thesis-default runs are used."
        ),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    specs = [parse_run_arg(item) for item in args.run] if args.run else list(DEFAULT_RUN_SPECS)
    report = build_report(outputs_root=Path(args.outputs_root), specs=specs)
    report_json, report_md = write_report(report, Path(args.output_dir))
    print(f"Wrote {report_json}")
    print(f"Wrote {report_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
