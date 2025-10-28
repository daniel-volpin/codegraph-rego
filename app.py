from fastapi import FastAPI, File, UploadFile, Form
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import os
import zipfile
import shutil
import subprocess
import uvicorn
from policy_integration import evaluate_policies
from llm_integration import explain_policy_violations

app = FastAPI()

# Allow CORS for local frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = "uploaded_code"


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
        zip_ref.extractall(UPLOAD_DIR)

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


@app.post("/search")
async def search(query: str = Form(...)):
    # You should refactor your hybrid search script to expose a function, or call as subprocess
    # For demo, let's assume you have a function hybrid_search(query)
    from hybrid_code_search import semantic_search, load_faiss_index, load_signature_map, load_embedding_model, get_neo4j_driver, fetch_graph_context_for_method, FAISS_INDEX_PATH, SIGNATURE_MAP_PATH, EMBEDDING_MODEL_NAME, NEO4J_URI, NEO4J_USER, NEO4J_PASS
    index = load_faiss_index(FAISS_INDEX_PATH)
    signature_map = load_signature_map(SIGNATURE_MAP_PATH)
    model = load_embedding_model(EMBEDDING_MODEL_NAME)
    neo4j_driver = get_neo4j_driver(NEO4J_URI, NEO4J_USER, NEO4J_PASS)
    matched_signatures = semantic_search(query, model, index, signature_map, k=5)
    graph_contexts = [fetch_graph_context_for_method(sig, neo4j_driver) for sig in matched_signatures]
    neo4j_driver.close()
    return {"matches": matched_signatures, "contexts": graph_contexts}


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
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/policy/evaluate_with_llm")
async def policy_evaluate_with_llm(limit: int = 10, model: str = "gpt-4o-mini"):
    """
    Evaluate Rego policies and have an LLM explain violations with remediation guidance.
    - Requires OPA CLI on PATH.
    - LLM is optional (uses OpenAI if OPENAI_API_KEY is set); otherwise returns snippets only.
    """
    res = evaluate_policies()
    if "violations" not in res:
        return JSONResponse(res, status_code=500)
    vio = res.get("violations", [])[:limit]
    enriched = explain_policy_violations(vio, max_items=limit, model=model)
    return {"violations": vio, "enriched": enriched}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
