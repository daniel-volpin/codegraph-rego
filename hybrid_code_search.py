"""
hybrid_query.py

Performs a hybrid search over the codebase: first retrieves semantically similar methods using FAISS,
then fetches their graph context from Neo4j for richer results.
"""


import faiss
import json
import os
from sentence_transformers import SentenceTransformer
from neo4j import GraphDatabase


INDEX_DIR = "index"
FAISS_INDEX_PATH = os.path.join(INDEX_DIR, "code_embeddings.index")
SIGNATURE_MAP_PATH = os.path.join(INDEX_DIR, "embedding_signature_map.json")
EMBEDDING_MODEL_NAME = "all-MiniLM-L6-v2"
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASS = "123456789"


def load_faiss_index(index_path: str):
    """
    Load the FAISS index from disk for semantic code search.
    """
    return faiss.read_index(index_path)


def load_signature_map(map_path: str):
    """
    Load the signature map from disk, mapping FAISS indices to method signatures.
    """
    with open(map_path, "r") as f:
        return json.load(f)


def load_embedding_model(model_name: str):
    """
    Load the sentence transformer model for generating code/query embeddings.
    """
    return SentenceTransformer(model_name)


def get_neo4j_driver(uri: str, user: str, password: str):
    """
    Create a Neo4j driver instance for database access.
    """
    return GraphDatabase.driver(uri, auth=(user, password))

def semantic_search(query: str, model, index, signature_map, k: int = 5):
    """
    Perform semantic search using FAISS and return top-k method signatures.
    """
    query_vector = model.encode([query])
    D, I = index.search(query_vector, k=k)
    return [signature_map[i] for i in I[0]]


def fetch_graph_context_for_method(sig: str, neo4j_driver):
    """
    Retrieve graph context (neighboring methods/classes) for a given method signature from Neo4j.
    Traverses CALLS, DECLARES, and NESTED_IN relationships up to 2 hops.
    """
    with neo4j_driver.session() as session:
        cypher = (
            """
            MATCH path=(m:Method {signature: $sig})-[:CALLS|DECLARES|NESTED_IN*1..2]-(n)
            RETURN m.signature AS method, collect(DISTINCT n.signature) AS neighbors
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
                print(f"      {neighbor},")
            print("    ]")



# Expose a function for FastAPI or other scripts
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