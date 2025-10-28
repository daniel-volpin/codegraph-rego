import logging
import os
import zipfile
import shutil
import uvicorn
from fastapi import FastAPI, File, UploadFile, Form, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from typing import Any

from codegraph.config import (
    UPLOAD_DIR,
    FAISS_INDEX_PATH,
    SIGNATURE_MAP_PATH,
    SIGNATURE_MAP_PATH_FULL,
    EMBEDDING_MODEL_NAME,
    LLM_MODEL,
)
from codegraph.db import get_neo4j_driver
from codegraph.ingestion.utils import safe_extract_zip, find_java_root
from codegraph.ingestion.service import ingest
from codegraph.embedding.service import EmbeddingService
from codegraph.api.models import (
    SearchResponse,
    MethodContext,
    Neighbor,
)
from codegraph.policy.service import evaluate as evaluate_policies, catalog as get_policy_catalog_entries
from codegraph.llm.integration import explain_policy_violations

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("codegraph.app")
os.environ["TOKENIZERS_PARALLELISM"] = "false"


app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)



@app.post("/upload")
async def upload_zip(file: UploadFile = File(...)) -> JSONResponse:
    """
    Upload a ZIP file containing code. Extracts, locates Java root, and triggers ingestion/embedding.
    """
    if not file.filename or not file.filename.endswith(".zip"):
        return JSONResponse({"error": "Only zip files allowed"}, status_code=400)

    # Clean and extract
    if os.path.exists(UPLOAD_DIR):
        shutil.rmtree(UPLOAD_DIR)
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    zip_path = os.path.join(UPLOAD_DIR, "code.zip")
    with open(zip_path, "wb") as f:
        f.write(await file.read())
    with zipfile.ZipFile(zip_path, "r") as zip_ref:
        safe_extract_zip(zip_ref, UPLOAD_DIR)

    java_root = find_java_root(UPLOAD_DIR)

    # Run ingestion and embedding directly
    if java_root is None:
        return JSONResponse({"error": "Java root directory not found in uploaded ZIP."}, status_code=400)
    ingest(java_root)
    EmbeddingService.build_embeddings()
    return JSONResponse({"status": "Codebase processed!", "java_root": java_root})


@app.on_event("startup")
async def _preload_resources() -> None:
    """Warm caches for search to improve first-request latency."""
    try:
        from codegraph.search.hybrid import (
            load_faiss_index,
            load_signature_map,
            load_embedding_model,
        )
        # Try full-signature map first, then legacy map
        try:
            load_signature_map(SIGNATURE_MAP_PATH_FULL)
        except Exception:
            load_signature_map(SIGNATURE_MAP_PATH)
        load_faiss_index(FAISS_INDEX_PATH)
        load_embedding_model(EMBEDDING_MODEL_NAME)
        logger.info("Search resources preloaded successfully.")
    except Exception as e:
        logger.warning(f"[startup] Skipping search preload: {e}")


@app.get("/health")
async def health() -> JSONResponse:
    """
    Readiness probe: checks Neo4j connectivity, FAISS index and signature map presence, model preload, and OPA CLI availability.
    """
    checks: dict[str, Any] = {
        "neo4j": False,
        "faiss_index": False,
        "signature_map": False,
        "embedding_model": False,
        "opa": False,
        "details": {},
    }
    # Neo4j
    try:
        drv = get_neo4j_driver()
        with drv.session() as s:
            s.run("RETURN 1").consume()
        drv.close()
        checks["neo4j"] = True
    except Exception as e:
        checks["details"]["neo4j"] = str(e)
    # Index + map + model
    try:
        from codegraph.search.hybrid import load_faiss_index, load_signature_map, load_embedding_model
        load_faiss_index(FAISS_INDEX_PATH)
        try:
            load_signature_map(SIGNATURE_MAP_PATH_FULL)
        except Exception:
            load_signature_map(SIGNATURE_MAP_PATH)
        checks["faiss_index"] = True
        checks["signature_map"] = True
        load_embedding_model(EMBEDDING_MODEL_NAME)
        checks["embedding_model"] = True
    except Exception as e:
        checks["details"]["search"] = str(e)
    # OPA presence
    try:
        if shutil.which("opa"):
            checks["opa"] = True
    except Exception:
        pass
    status = 200 if all([checks["neo4j"], checks["faiss_index"], checks["signature_map"]]) else 503
    return JSONResponse(checks, status_code=status)


@app.post("/search")
async def search(query: str = Form(...)):
    # You should refactor your hybrid search script to expose a function, or call as subprocess
    # For demo, let's assume you have a function hybrid_search(query)
    try:
        from codegraph.search.service import run_search
        matched_signatures, graph_contexts = run_search(query, k=5)
        contexts_model = []
        for ctx in graph_contexts:
            ctx_entries = []
            for entry in ctx:
                neighbors = [Neighbor(**n) for n in entry.get("neighbors", [])]
                ctx_entries.append(MethodContext(method=entry.get("method", ""), neighbors=neighbors))
            contexts_model.append(ctx_entries)
        return SearchResponse(matches=matched_signatures, contexts=contexts_model)
    except FileNotFoundError as e:
        logger.warning(f"Search file not found: {e}")
        return JSONResponse({"error": str(e)}, status_code=400)
    except Exception as e:
        logger.error(f"Search failed: {e}")
        return JSONResponse({"error": f"search_failed: {e}"}, status_code=500)


@app.get("/policy/evaluate")
async def policy_evaluate():
    """
    Evaluate Rego policies against the current Neo4j code graph.
    Requires OPA CLI installed and available on PATH.
    """
    try:
        result = evaluate_policies()
        status = 200 if "violations" in result or "opa_output" in result else 500
        return JSONResponse(result, status_code=status)
    except Exception as e:
        logger.error(f"Policy evaluation failed: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/policy/evaluate_with_llm")
async def policy_evaluate_with_llm(limit: int = 10, model: str | None = None):
    """
    Evaluate Rego policies and have an LLM explain violations with remediation guidance.
    - Requires OPA CLI on PATH.
    - LLM is optional (uses OpenAI if OPENAI_API_KEY is set); otherwise returns snippets only.
    """
    res = evaluate_policies()
    if "violations" not in res:
        return JSONResponse(res, status_code=500)
    vio = res.get("violations", [])[:limit]
    enriched = explain_policy_violations(vio, max_items=limit, model=model or LLM_MODEL)
    return JSONResponse({"violations": vio, "enriched": enriched})


@app.get("/policy/catalog")
async def policy_catalog():
    """
    Return the policy catalog describing available controls, their evidence requirements, and Rego linkage.
    """
    try:
        controls = get_policy_catalog_entries()
        # Ensure stable ordering by control identifier
        controls_sorted = sorted(controls, key=lambda item: item.get("control") or item.get("id") or "")
        return JSONResponse({"controls": controls_sorted})
    except Exception as exc:
        logger.error(f"Policy catalog error: {exc}")
        return JSONResponse({"error": str(exc)}, status_code=500)

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled error: {exc}")
    return JSONResponse(status_code=500, content={"error": "Internal server error", "details": str(exc)})
if __name__ == "__main__":
    logger.info("Starting FastAPI app...")
    uvicorn.run(app, host="0.0.0.0", port=8000)
