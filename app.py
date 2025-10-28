import os
os.environ["TOKENIZERS_PARALLELISM"] = "false"
import zipfile
import shutil
import logging
import uvicorn
from typing import Any

# Third-party
from fastapi import FastAPI, File, UploadFile, Form, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

# Local imports
from codegraph.policy.service import evaluate as evaluate_policies
from codegraph.policy.service import catalog as get_policy_catalog_entries
from codegraph.llm.integration import explain_policy_violations
from codegraph.config import (
    UPLOAD_DIR,
    FAISS_INDEX_PATH,
    SIGNATURE_MAP_PATH,
    SIGNATURE_MAP_PATH_FULL,
    EMBEDDING_MODEL_NAME,
    LLM_MODEL,
)
from typing import Any

from codegraph.db import get_neo4j_driver
from codegraph.api.models import (
    SearchResponse,
    EvaluateResponse,
    EvaluateWithLLMResponse,
    PolicyCatalogResponse,
    PolicyViolation,
    ControlMetadata,
    LLMEnrichedItem,

    MethodContext,
)
from codegraph.ingestion.utils import safe_extract_zip, find_java_root

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

# Allow CORS for local frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


from codegraph.api.services.upload_service import handle_upload
from codegraph.api.services.policy_service import (
    handle_policy_evaluate,
    handle_policy_evaluate_with_llm,
    handle_policy_catalog,
)
from codegraph.api.services.search_service import handle_search
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
    if java_root is None:
        logger.error("Java root directory not found in uploaded ZIP.")
        return JSONResponse({"error": "java_root_not_found"}, status_code=400)

    # Run ingestion and embedding directly (no subprocess)
    try:
        from codegraph.ingestion.service import ingest
        from codegraph.embedding.service import EmbeddingService

        ingest(java_root)
        EmbeddingService.build_embeddings()
    except Exception as e:
        logger.error(f"Processing failed: {e}")
        return JSONResponse({"error": f"processing_failed: {e}"}, status_code=500)
    result, status = handle_upload(file)
    return JSONResponse(result, status_code=status)


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


@app.post("/search", response_model=SearchResponse)
async def search(query: str = Form(...)) -> SearchResponse | JSONResponse:
    """
    Search for code elements using hybrid semantic and graph-based search.
    """
    try:
        from codegraph.search.service import run_search
        matched_signatures, graph_contexts = run_search(query, k=5)
        # Convert to models explicitly
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

@app.get("/policy/evaluate", response_model=EvaluateResponse)
async def policy_evaluate() -> EvaluateResponse | JSONResponse:
    """
    Evaluate Rego policies against the current Neo4j code graph.
    Requires OPA CLI installed and available on PATH.
    """
    try:
        modeled = handle_policy_evaluate()
        status = 200 if modeled.violations or modeled.opa_output else 500
        return JSONResponse(modeled.dict(by_alias=True), status_code=status)
    except Exception as e:
        logger.error(f"Policy evaluation failed: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/policy/evaluate_with_llm", response_model=EvaluateWithLLMResponse)
async def policy_evaluate_with_llm(limit: int = 10, model: str | None = None) -> EvaluateWithLLMResponse | JSONResponse:
    """
    Evaluate Rego policies and have an LLM explain violations with remediation guidance.
    - Requires OPA CLI on PATH.
    - LLM is optional (uses OpenAI if OPENAI_API_KEY is set); otherwise returns snippets only.
    """
    try:
        modeled = handle_policy_evaluate_with_llm(limit=limit, model=model or LLM_MODEL)
        return JSONResponse(modeled.dict(by_alias=True), status_code=200)
    except Exception as e:
        logger.error(f"LLM policy evaluation failed: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/policy/catalog", response_model=PolicyCatalogResponse)
async def policy_catalog() -> PolicyCatalogResponse | JSONResponse:
    """
    Return the policy catalog describing available controls, their evidence requirements, and Rego linkage.
    """
    try:
        modeled = handle_policy_catalog()
        return JSONResponse(modeled.dict(by_alias=True), status_code=200)
    except ValueError as exc:
        logger.error(f"Policy catalog error: {exc}")
        return JSONResponse({"error": str(exc)}, status_code=500)

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled error: {exc}")
    return JSONResponse(status_code=500, content={"error": "Internal server error", "details": str(exc)})
if __name__ == "__main__":
    logger.info("Starting FastAPI app...")
    uvicorn.run(app, host="0.0.0.0", port=8000)
