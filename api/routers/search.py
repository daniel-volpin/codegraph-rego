import asyncio
import logging

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from api.models.validation import SearchRequest, SearchResponse, SearchMatch
from codegraph.search.service import run_search

router = APIRouter()
logger = logging.getLogger("codegraph.api.routers.search")


@router.post("/search", response_model=SearchResponse)
async def search(request: SearchRequest):
    try:
        # F08: run_search exercises FAISS + Neo4j synchronously; hop to a
        # worker thread to keep the event loop unblocked.
        matched_signatures, graph_contexts = await asyncio.to_thread(
            run_search, request.query, k=5
        )
        contexts_model = []
        for ctx in graph_contexts:
            ctx_entries = []
            for entry in ctx:
                neighbors = [dict(neighbor) for neighbor in entry.get("neighbors", [])]
                ctx_entries.append(SearchMatch(method=entry.get("method", ""), neighbors=neighbors))
            contexts_model.append(ctx_entries)
        return SearchResponse(matches=matched_signatures, contexts=contexts_model)
    except FileNotFoundError as e:
        logger.warning(f"Search file not found: {e}")
        return JSONResponse({"error": str(e)}, status_code=400)
    except Exception as e:
        logger.error(f"Search failed: {e}")
        return JSONResponse({"error": f"search_failed: {e}"}, status_code=500)
