from fastapi import FastAPI, File, UploadFile, Form
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import os
import zipfile
import shutil
import subprocess
import uvicorn
from policy.service import evaluate as evaluate_policies
from policy.service import catalog as get_policy_catalog_entries
from llm_integration import explain_policy_violations
from config import (
    UPLOAD_DIR,
    FAISS_INDEX_PATH,
    SIGNATURE_MAP_PATH,
    SIGNATURE_MAP_PATH_FULL,
    EMBEDDING_MODEL_NAME,
    LLM_MODEL,
)
from db import get_neo4j_driver
from api_models import (
    SearchResponse,
    EvaluateResponse,
    EvaluateWithLLMResponse,
    PolicyCatalogResponse,
    PolicyViolation,
    ControlMetadata,
    LLMEnrichedItem,
)

app = FastAPI()

# Allow CORS for local frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _safe_extract_zip(zip_file: zipfile.ZipFile, dest_dir: str) -> None:
    """
    Safely extract a ZIP to dest_dir, preventing Zip Slip path traversal.
    """
    dest_root = os.path.realpath(dest_dir)
    for member in zip_file.infolist():
        member_path = os.path.realpath(os.path.join(dest_dir, member.filename))
        if not member_path.startswith(dest_root + os.sep) and member_path != dest_root:
            # Skip suspicious entries
            continue
        if member.is_dir():
            os.makedirs(member_path, exist_ok=True)
        else:
            os.makedirs(os.path.dirname(member_path), exist_ok=True)
            with zip_file.open(member, "r") as src, open(member_path, "wb") as dst:
                shutil.copyfileobj(src, dst)


@app.post("/upload")
async def upload_zip(file: UploadFile = File(...)):
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
        _safe_extract_zip(zip_ref, UPLOAD_DIR)

    # Try to locate a Java source root (src/main/java) within the uploaded folder
    def find_java_root(base: str) -> str:
        for root, dirs, files in os.walk(base):
            # normalize path separators across OSes
            if root.replace(os.sep, "/").endswith("src/main/java"):
                return root
        return base

    java_root = find_java_root(UPLOAD_DIR)

    # Run your parsing and embedding scripts (adjust paths as needed)
    env = {**os.environ, "JAVA_ROOT_DIR": java_root}
    subprocess.run(["python3", "codebase_to_neo4j.py"], check=True, env=env)
    subprocess.run(["python3", "build_code_embeddings.py"], check=True)
    return {"status": "Codebase processed!", "java_root": java_root}


@app.on_event("startup")
async def _preload_resources():
    """Warm caches for search to improve first-request latency."""
    try:
        from hybrid_code_search import (
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
    except Exception as e:
        # Non-fatal; index may not exist yet before first upload/build
        print(f"[startup] Skipping search preload: {e}")


@app.get("/health")
async def health():
    """Readiness probe: checks Neo4j connectivity, FAISS index and signature map presence, model preload, and OPA CLI availability."""
    checks = {
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
        from hybrid_code_search import load_faiss_index, load_signature_map, load_embedding_model
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
async def search(query: str = Form(...)):
    # You should refactor your hybrid search script to expose a function, or call as subprocess
    # For demo, let's assume you have a function hybrid_search(query)
    try:
        from search.service import run_search
        matched_signatures, graph_contexts = run_search(query, k=5)
        return {"matches": matched_signatures, "contexts": graph_contexts}
    except FileNotFoundError as e:
        return JSONResponse({"error": str(e)}, status_code=400)
    except Exception as e:
        return JSONResponse({"error": f"search_failed: {e}"}, status_code=500)


@app.get("/policy/evaluate", response_model=EvaluateResponse)
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
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/policy/evaluate_with_llm", response_model=EvaluateWithLLMResponse)
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
    return {"violations": vio, "enriched": enriched}


@app.get("/policy/catalog", response_model=PolicyCatalogResponse)
async def policy_catalog():
    """
    Return the policy catalog describing available controls, their evidence requirements, and Rego linkage.
    """
    try:
        controls = get_policy_catalog_entries()
        # Ensure stable ordering by control identifier
        controls_sorted = sorted(controls, key=lambda item: item.get("control") or item.get("id") or "")
        return {"controls": controls_sorted}
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=500)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
