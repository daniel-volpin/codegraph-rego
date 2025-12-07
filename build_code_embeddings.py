"""
CLI wrapper to rebuild FAISS/embedding artifacts from the current Neo4j graph.
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
    parser = argparse.ArgumentParser(description="Build semantic code embeddings.")
    parser.add_argument("--neo4j-uri", default=config.NEO4J_URI, help="Neo4j Bolt URI")
    parser.add_argument("--neo4j-user", default=config.NEO4J_USER, help="Neo4j username")
    parser.add_argument("--neo4j-pass", default=config.NEO4J_PASS, help="Neo4j password")
    parser.add_argument(
        "--model",
        default=config.EMBEDDING_MODEL_NAME,
        help="SentenceTransformer model id (default: %(default)s)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress progress callbacks (only log essentials)",
    )
    return parser.parse_args(argv)


def main(argv: List[str] | None = None) -> int:
    args = parse_args(argv)
    import codegraph.embedding.service as embedding_module

    # override module-level constants so the service picks up CLI overrides
    embedding_module.NEO4J_URI = args.neo4j_uri
    embedding_module.NEO4J_USER = args.neo4j_user
    embedding_module.NEO4J_PASS = args.neo4j_pass
    embedding_module.EMBEDDING_MODEL_NAME = args.model

    callback = None if args.quiet else _progress
    embedding_module.EmbeddingService.build_embeddings(progress_callback=callback)
    return 0


if __name__ == "__main__":
    sys.exit(main())
