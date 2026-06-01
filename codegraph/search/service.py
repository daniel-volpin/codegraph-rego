from __future__ import annotations

from typing import Any, Dict, List, Tuple

from codegraph.config import settings
from codegraph.db import get_neo4j_driver
from codegraph.search.hybrid import (
    load_faiss_index,
    load_signature_map,
    load_embedding_model,
    semantic_search,
    fetch_graph_context_for_method,
)


class HybridSearchService:
    """
    Thin wrapper around the hybrid search helpers so other layers (policy/LLM)
    can fetch similar methods or graph context without re-implementing the glue.
    """

    def __init__(
        self,
        index_path: str = settings.faiss_index_path,
        signature_map_candidates: Tuple[str, ...] = (
            settings.signature_map_path_full,
            settings.signature_map_path,
        ),
        model_name: str = settings.embedding_model_name,
    ):
        self._index_path = index_path
        self._signature_map_candidates = signature_map_candidates
        self._model_name = model_name

    def _load_index(self):
        return load_faiss_index(self._index_path)

    def _load_signature_map(self) -> List[str]:
        last_exc: Exception | None = None
        for path in self._signature_map_candidates:
            try:
                return load_signature_map(path)
            except FileNotFoundError as exc:
                last_exc = exc
        if last_exc:
            raise last_exc
        raise FileNotFoundError("No signature map candidates available")

    def _load_model(self):
        return load_embedding_model(self._model_name)

    def search(self, query: str, top_k: int = 5) -> List[str]:
        index = self._load_index()
        signature_map = self._load_signature_map()
        model = self._load_model()
        return semantic_search(query, model, index, signature_map, k=top_k)

    def similar_to_signature(self, signature: str, top_k: int = 3) -> List[str]:
        """
        Run a light-weight semantic search using the signature as a textual query.
        Returns similar signatures (excluding duplicates of the input).
        """
        matches = self.search(signature, top_k=top_k + 1)
        deduped = [sig for sig in matches if sig != signature]
        return deduped[:top_k]


def run_search(query: str, k: int = 5) -> Tuple[List[str], List[List[Dict[str, Any]]]]:
    """
    Execute hybrid search using cached FAISS index, signature map, and embedding model.
    Returns (matches, contexts) where contexts aligns with the matches order.
    """
    service = HybridSearchService()
    matches = service.search(query, top_k=k)
    contexts: List[List[Dict[str, Any]]] = []
    if matches:
        driver = get_neo4j_driver()
        try:
            contexts = [fetch_graph_context_for_method(sig, driver) for sig in matches]
        finally:
            driver.close()
    return matches, contexts
