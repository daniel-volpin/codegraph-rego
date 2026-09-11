"""
CLI wrapper to parse a Java project into Neo4j using the ingestion service.
Intended for Chapter 4 evaluation runs.
"""

from __future__ import annotations

import argparse
import sys

from codegraph.config import settings


def _progress(phase: str, message: str, progress: float) -> None:
    pct = f"{progress:.1f}".rjust(5)
    print(f"[{phase:<10}] {pct}% {message}")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Publish a JDT workspace revision. Neo4j connection uses CodeGraph runtime settings.",
    )
    parser.add_argument(
        "--java-root",
        default=settings.java_root_dir,
        help="Path to Java source root (default: %(default)s)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the workspace to be published without accessing Neo4j",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    from codegraph.ingestion import service as ingestion_service

    if args.dry_run:
        print("Dry run: would ingest with settings:")
        print(f"  java_root : {args.java_root}")
        return 0

    ingestion_service.ingest(args.java_root, progress_callback=_progress)
    return 0


if __name__ == "__main__":
    sys.exit(main())
