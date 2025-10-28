"""
hybrid_code_search.py (CLI)

Thin wrapper around the search package to run a hybrid search from the
command line, preserving the original entry point while reducing script
coupling.
"""

from typing import List

from search.service import run_search


def print_top_matches(matches: List[str]) -> None:
    print("\nTop Matches:")
    for sig in matches:
        print(f"  - {sig}")


def print_graph_contexts(graph_contexts):
    print("\nGraph Contexts:")
    for ctx in graph_contexts:
        for entry in ctx:
            print(f"  Method: {entry['method']}")
            print("    Neighbors: [")
            for neighbor in entry['neighbors']:
                print(f"      ({neighbor.get('type')}): {neighbor.get('id')},")
            print("    ]")


def hybrid_search(query: str, k: int = 5):
    return run_search(query, k=k)


if __name__ == "__main__":
    query = "Where is access control enforced?"
    matches, contexts = run_search(query, k=5)
    print_top_matches(matches)
    print_graph_contexts(contexts)
