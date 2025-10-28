from __future__ import annotations

from typing import Any, Dict, List, Tuple

from config import (
    FAISS_INDEX_PATH,
    SIGNATURE_MAP_PATH,
    SIGNATURE_MAP_PATH_FULL,
    EMBEDDING_MODEL_NAME,
)
from db import get_neo4j_driver
from search.hybrid import (
    load_faiss_index,
    load_signature_map,
    load_embedding_model,
    semantic_search,
    fetch_graph_context_for_method,
)


def run_search(query: str, k: int = 5) -> Tuple[List[str], List[List[Dict[str, Any]]]]:
    """
    Execute hybrid search using cached FAISS index, signature map, and embedding model.
    Returns (matches, contexts) where contexts aligns with the matches order.
    """
    index = load_faiss_index(FAISS_INDEX_PATH)
    # Prefer full-signature map; fallback to legacy
    try:
        signature_map = load_signature_map(SIGNATURE_MAP_PATH_FULL)
    except Exception:
        signature_map = load_signature_map(SIGNATURE_MAP_PATH)
    model = load_embedding_model(EMBEDDING_MODEL_NAME)
    driver = get_neo4j_driver()
    try:
        matches = semantic_search(query, model, index, signature_map, k=k)
        contexts = [fetch_graph_context_for_method(sig, driver) for sig in matches]
    finally:
        driver.close()
    return matches, contexts
