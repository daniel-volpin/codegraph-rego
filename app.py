from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import logging
import os

os.environ["TOKENIZERS_PARALLELISM"] = "false"
from api.routers.upload import router as upload_router
from api.routers.health import router as health_router
from api.routers.search import router as search_router
from api.routers.policy import router as policy_router
from api.routers.remediation import router as remediation_router

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(levelname)s [%(name)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("codegraph.app")

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(upload_router)
app.include_router(health_router)
app.include_router(search_router)
app.include_router(policy_router)
app.include_router(remediation_router)


@app.on_event("startup")
async def _preload_resources():
    try:
        from codegraph.search.hybrid import (
            load_faiss_index,
            load_signature_map,
            load_embedding_model,
        )
        from codegraph.config import (
            FAISS_INDEX_PATH,
            SIGNATURE_MAP_PATH,
            SIGNATURE_MAP_PATH_FULL,
            EMBEDDING_MODEL_NAME,
            JAVA_ROOT_DIR,
        )
        from codegraph.ingestion.service import ingest

        logger.info("Starting automatic graph synchronization...")
        try:
            # Sync graph (prune stale nodes) on startup
            ingest(JAVA_ROOT_DIR, sync=True)
        except Exception as exc:
            logger.error(f"Startup ingestion failed: {exc}")

        try:
            load_signature_map(SIGNATURE_MAP_PATH_FULL)
        except Exception:
            load_signature_map(SIGNATURE_MAP_PATH)
        load_faiss_index(FAISS_INDEX_PATH)
        load_embedding_model(EMBEDDING_MODEL_NAME)
        logger.info("Search resources preloaded successfully.")
    except Exception as e:
        logger.warning(f"[startup] Skipping search preload: {e}")


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled error: {exc}")
    return JSONResponse(status_code=500, content={"error": "Internal server error", "details": str(exc)})


if __name__ == "__main__":
    import uvicorn

    logger.info("Starting FastAPI app...")
    uvicorn.run(app, host="0.0.0.0", port=8000)
