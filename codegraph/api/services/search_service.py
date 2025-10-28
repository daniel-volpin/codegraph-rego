from codegraph.search.service import run_search
from codegraph.api.models import SearchResponse, Neighbor, MethodContext
import logging

logger = logging.getLogger(__name__)

def handle_search(query: str, k: int = 5) -> SearchResponse:
    matched_signatures, graph_contexts = run_search(query, k=k)
    contexts_model = []
    for ctx in graph_contexts:
        ctx_entries = []
        for entry in ctx:
            neighbors = [Neighbor(**n) for n in entry.get("neighbors", [])]
            ctx_entries.append(MethodContext(method=entry.get("method", ""), neighbors=neighbors))
        contexts_model.append(ctx_entries)
    return SearchResponse(matches=matched_signatures, contexts=contexts_model)
