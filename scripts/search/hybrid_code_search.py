"""
CLI helper to run the hybrid semantic + graph search pipeline.
"""

from __future__ import annotations

import argparse
import json
import sys


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Search the active graph/index generation using CodeGraph runtime settings.",
    )
    parser.add_argument("query", help="Natural language query to search for")
    parser.add_argument(
        "-k",
        "--top-k",
        type=int,
        default=5,
        help="Number of semantic matches to return (default: %(default)s)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON output instead of pretty printing",
    )
    return parser.parse_args(argv)


def _print_results(matches: list[str], contexts: list[list[dict]], as_json: bool) -> None:
    if as_json:
        print(json.dumps({"matches": matches, "contexts": contexts}, indent=2))
        return
    for idx, method_key in enumerate(matches, start=1):
        print(f"[{idx}] {method_key}")
        for context in contexts[idx - 1]:
            print(f"    {context['method']}")
            for neighbor in context["neighbors"]:
                print(f"    - ({neighbor['type']}) {neighbor['display']} [{neighbor['id']}]")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    from codegraph.search import service as search_service

    matches, contexts = search_service.run_search(args.query, k=args.top_k)
    _print_results(matches, contexts, as_json=args.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())
