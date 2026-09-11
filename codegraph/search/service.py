from __future__ import annotations

from typing import Any

from codegraph.config import settings
from codegraph.db import shared_neo4j_driver
from codegraph.search.hybrid import (
    fetch_graph_context_for_method,
    load_embedding_model,
    load_search_artifacts_bundle,
    semantic_search,
    semantic_search_by_method_vector,
    validate_retrieval_generation,
)


class HybridSearchService:
    """
    Thin wrapper around the hybrid search helpers so other layers (policy/LLM)
    can fetch similar methods or graph context without re-implementing the glue.
    """

    def __init__(
        self,
        index_path: str | None = None,
        signature_map_path: str | None = None,
        model_name: str | None = None,
    ):
        # Resolved at construction, not import: default-argument expressions
        # would freeze settings values before tests or env overrides apply.
        self._index_path = index_path or settings.faiss_index_path
        self._signature_map_path = signature_map_path or settings.signature_map_path_full
        self._model_name = model_name or settings.embedding_model_name

    def _load_artifacts_bundle(self):
        return load_search_artifacts_bundle(index_path=self._index_path, signature_map_path=self._signature_map_path)

    def _load_model(self):
        return load_embedding_model(self._model_name)

    def search(self, query: str, top_k: int = 5) -> list[str]:
        bundle = self._load_artifacts_bundle()
        model = self._load_model()
        return semantic_search(
            query,
            model,
            bundle.index,
            bundle.signature_map,
            k=top_k,
            generation=bundle.generation,
            expected_model_name=self._model_name,
        )

    def similar_to_method_key(self, method_key: str, top_k: int = 3) -> list[str]:
        """
        Run semantic neighbor search from the stored vector for a canonical method key.
        """
        bundle = self._load_artifacts_bundle()
        return semantic_search_by_method_vector(method_key, bundle.index, bundle.signature_map, k=top_k)


def run_search(query: str, k: int = 5) -> tuple[list[str], list[list[dict[str, Any]]]]:
    """
    Execute hybrid search using cached FAISS index, method-key map, and embedding model.
    Returns (matches, contexts) where contexts aligns with the matches order.
    """
    service = HybridSearchService()
    driver = shared_neo4j_driver()
    validate_retrieval_generation(driver)
    matches = service.search(query, top_k=k)
    contexts: list[list[dict[str, Any]]] = []
    if matches:
        contexts = [fetch_graph_context_for_method(sig, driver) for sig in matches]
    return matches, contexts
