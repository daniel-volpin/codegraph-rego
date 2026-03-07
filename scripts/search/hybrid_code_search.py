"""
CLI helper to run the hybrid semantic + graph search pipeline.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List

from codegraph import config


def parse_args(argv: List[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run hybrid semantic code search.")
    parser.add_argument("query", help="Natural language query to search for")
    parser.add_argument(
        "-k",
        "--top-k",
        type=int,
        default=5,
        help="Number of semantic matches to return (default: %(default)s)",
    )
    parser.add_argument("--index-path", default=config.FAISS_INDEX_PATH, help="FAISS index path")
    parser.add_argument("--signature-map", default=config.SIGNATURE_MAP_PATH_FULL, help="Signature map path")
    parser.add_argument(
        "--legacy-signature-map",
        default=config.SIGNATURE_MAP_PATH,
        help="Legacy signature map path",
    )
    parser.add_argument(
        "--model",
        default=config.EMBEDDING_MODEL_NAME,
        help="SentenceTransformer model id",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON output instead of pretty printing",
    )
    return parser.parse_args(argv)


def _print_results(matches: List[str], contexts: List[List[dict]], as_json: bool) -> None:
    if as_json:
        print(json.dumps({"matches": matches, "contexts": contexts}, indent=2))
        return
    for idx, sig in enumerate(matches, start=1):
        print(f"[{idx}] {sig}")
        for neighbor in contexts[idx - 1]:
            rel = neighbor.get("relationship")
            node_type = neighbor.get("type")
            target = neighbor.get("target")
            print(f"    - {rel}: ({node_type}) {target}")


def main(argv: List[str] | None = None) -> int:
    args = parse_args(argv)

    from codegraph.search import service as search_service

    # Override module-level constants to honor CLI inputs.
    search_service.FAISS_INDEX_PATH = args.index_path
    search_service.SIGNATURE_MAP_PATH = args.legacy_signature_map
    search_service.SIGNATURE_MAP_PATH_FULL = args.signature_map
    search_service.EMBEDDING_MODEL_NAME = args.model

    matches, contexts = search_service.run_search(args.query, k=args.top_k)
    _print_results(matches, contexts, as_json=args.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
