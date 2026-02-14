"""
CLI wrapper to parse a Java project into Neo4j using the ingestion service.
Intended for Chapter 4 evaluation runs.
"""

from __future__ import annotations

import argparse
import sys
from typing import List

from codegraph import config


def _progress(phase: str, message: str, progress: float) -> None:
    pct = f"{progress:.1f}".rjust(5)
    print(f"[{phase:<10}] {pct}% {message}")


def parse_args(argv: List[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Ingest Java sources into Neo4j.")
    parser.add_argument(
        "--java-root",
        default=config.JAVA_ROOT_DIR,
        help="Path to Java source root (default: %(default)s)",
    )
    parser.add_argument("--neo4j-uri", default=config.NEO4J_URI, help="Neo4j Bolt URI")
    parser.add_argument("--neo4j-user", default=config.NEO4J_USER, help="Neo4j username")
    parser.add_argument("--neo4j-pass", default=config.NEO4J_PASS, help="Neo4j password")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print effective settings without writing to Neo4j",
    )
    parser.add_argument(
        "--sync",
        action="store_true",
        help="Prune stale files from the graph",
    )
    return parser.parse_args(argv)


def main(argv: List[str] | None = None) -> int:
    args = parse_args(argv)

    from codegraph.ingestion import service as ingestion_service

    # allow CLI overrides without re-importing the module
    ingestion_service.NEO4J_URI = args.neo4j_uri
    ingestion_service.NEO4J_USER = args.neo4j_user
    ingestion_service.NEO4J_PASS = args.neo4j_pass

    if args.dry_run:
        print("Dry run: would ingest with settings:")
        print(f"  java_root : {args.java_root}")
        print(f"  neo4j_uri : {args.neo4j_uri}")
        print(f"  neo4j_user: {args.neo4j_user}")
        print(f"  sync      : {args.sync}")
        return 0

    ingestion_service.ingest(args.java_root, progress_callback=_progress, sync=args.sync)
    return 0


if __name__ == "__main__":
    sys.exit(main())
