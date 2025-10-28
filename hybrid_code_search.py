"""
hybrid_code_search.py

Performs a hybrid search over the codebase: first retrieves semantically similar methods using FAISS,
then fetches their graph context from Neo4j for richer results.
Now caches model/index/map in-process and uses cosine similarity (IP over normalized vectors).
"""


import faiss  # type: ignore
import json
import os
from sentence_transformers import SentenceTransformer
from neo4j import GraphDatabase
from config import (
    FAISS_INDEX_PATH,
    SIGNATURE_MAP_PATH,
    EMBEDDING_MODEL_NAME,
    NEO4J_URI,
    NEO4J_USER,
    NEO4J_PASS,
    SIGNATURE_MAP_PATH_FULL,
)

# Simple in-process caches
_INDEX = None
_SIGMAP = None
_MODEL = None


def load_faiss_index(index_path: str):
    """
    Load the FAISS index from disk for semantic code search (cached).
    """
    global _INDEX
    if _INDEX is not None:
        return _INDEX
    if not os.path.isfile(index_path):
        raise FileNotFoundError(f"FAISS index not found at {index_path}. Build embeddings first.")
    _INDEX = faiss.read_index(index_path)
    return _INDEX


def load_signature_map(map_path: str):
    """
    Load the signature map from disk, mapping FAISS indices to method full-signatures (cached).
    Tries the preferred full-signature map first, then falls back to provided path and the legacy path.
    """
    global _SIGMAP
    if _SIGMAP is not None:
        return _SIGMAP
    candidates = [SIGNATURE_MAP_PATH_FULL, map_path, SIGNATURE_MAP_PATH]
    last_exc = None
    for p in candidates:
        try:
            if os.path.isfile(p):
                with open(p, "r") as f:
                    _SIGMAP = json.load(f)
                    return _SIGMAP
        except Exception as e:
            last_exc = e
    raise FileNotFoundError(
        f"Signature map not found. Tried: {', '.join(candidates)}" + (f". Last error: {last_exc}" if last_exc else "")
    )


def load_embedding_model(model_name: str):
    """
    Load the sentence transformer model for generating code/query embeddings (cached).
    """
    global _MODEL
    if _MODEL is None:
        _MODEL = SentenceTransformer(model_name)
    return _MODEL


def get_neo4j_driver(uri: str, user: str, password: str):
    """
    Create a Neo4j driver instance for database access.
    """
    return GraphDatabase.driver(uri, auth=(user, password))


def semantic_search(query: str, model, index, signature_map, k: int = 5):
    """
    Perform semantic search over normalized embeddings using FAISS (IP) and return top-k method identifiers.
    The identifiers are `full_signature` values produced during embedding (or `signature` as fallback).
    """
    query_vector = model.encode([query], normalize_embeddings=True)
    D, indices = index.search(query_vector, k=k)
    return [signature_map[i] for i in indices[0]]


def fetch_graph_context_for_method(sig: str, neo4j_driver):
    """
    Retrieve graph context (neighboring methods/classes) for a given method signature from Neo4j.
    Traverses CALLS, DECLARES, and NESTED_IN relationships up to 2 hops.
    Returns typed neighbors to avoid None values for Classes.
    """
    with neo4j_driver.session() as session:
        cypher = (
            """
            MATCH (m:Method)
            WHERE m.signature = $sig OR m.full_signature = $sig
            MATCH path=(m)-[:CALLS|DECLARES|NESTED_IN*1..2]-(n)
            RETURN coalesce(m.full_signature, m.signature) AS method,
                   collect(DISTINCT CASE
                     WHEN n:Method THEN {type: 'Method', id: coalesce(n.full_signature, n.signature)}
                     WHEN n:Class  THEN {type: 'Class',  id: n.fqn}
                     ELSE {type: 'Node', id: coalesce(n.signature, n.fqn, n.name)}
                   END) AS neighbors
            """
        )
        result = session.run(cypher, sig=sig)
        return [record.data() for record in result]


def print_top_matches(matches):
    """
    Print the top matched method signatures from semantic search.
    """
    print("\nTop Matches:")
    for sig in matches:
        print(f"  - {sig}")


def print_graph_contexts(graph_contexts):
    """
    Print the graph context (neighbors) for each matched method.
    """
    print("\nGraph Contexts:")
    for ctx in graph_contexts:
        for entry in ctx:
            print(f"  Method: {entry['method']}")
            print("    Neighbors: [")
            for neighbor in entry['neighbors']:
                print(f"      ({neighbor.get('type')}): {neighbor.get('id')},")
            print("    ]")


def hybrid_search(query: str, k: int = 5):
    """
    Perform hybrid semantic/graph search for a user query.
    Returns a tuple: (matched_signatures, graph_contexts)
    """
    index = load_faiss_index(FAISS_INDEX_PATH)
    signature_map = load_signature_map(SIGNATURE_MAP_PATH)
    model = load_embedding_model(EMBEDDING_MODEL_NAME)
    neo4j_driver = get_neo4j_driver(NEO4J_URI, NEO4J_USER, NEO4J_PASS)
    matched_signatures = semantic_search(query, model, index, signature_map, k=k)
    graph_contexts = [fetch_graph_context_for_method(sig, neo4j_driver) for sig in matched_signatures]
    neo4j_driver.close()
    return matched_signatures, graph_contexts


if __name__ == "__main__":
    # For CLI usage/testing
    query = "Where is access control enforced?"
    matches, contexts = hybrid_search(query, k=5)
    print_top_matches(matches)
    print_graph_contexts(contexts)
