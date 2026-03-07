from __future__ import annotations

import logging
import os

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from api.routers.health import router as health_router
from api.routers.policy import router as policy_router
from api.routers.remediation import router as remediation_router
from api.routers.search import router as search_router
from api.routers.upload import router as upload_router

LOGGER = logging.getLogger("codegraph.app")


def _configure_runtime() -> None:
    os.environ["TOKENIZERS_PARALLELISM"] = "false"
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


async def _preload_resources() -> None:
    try:
        from codegraph.config import (
            EMBEDDING_MODEL_NAME,
            FAISS_INDEX_PATH,
            JAVA_ROOT_DIR,
            SIGNATURE_MAP_PATH,
            SIGNATURE_MAP_PATH_FULL,
        )
        from codegraph.ingestion.service import ingest
        from codegraph.search.hybrid import load_embedding_model, load_faiss_index, load_signature_map

        LOGGER.info("Starting automatic graph synchronization...")
        try:
            ingest(JAVA_ROOT_DIR, sync=True)
        except Exception as exc:
            LOGGER.error("Startup ingestion failed: %s", exc)

        try:
            load_signature_map(SIGNATURE_MAP_PATH_FULL)
        except Exception:
            load_signature_map(SIGNATURE_MAP_PATH)
        load_faiss_index(FAISS_INDEX_PATH)
        load_embedding_model(EMBEDDING_MODEL_NAME)
        LOGGER.info("Search resources preloaded successfully.")
    except Exception as exc:
        LOGGER.warning("[startup] Skipping search preload: %s", exc)


async def _generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    LOGGER.error("Unhandled error on %s: %s", request.url.path, exc)
    return JSONResponse(status_code=500, content={"error": "Internal server error", "details": str(exc)})


def create_app() -> FastAPI:
    _configure_runtime()
    application = FastAPI()
    application.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    application.include_router(upload_router)
    application.include_router(health_router)
    application.include_router(search_router)
    application.include_router(policy_router)
    application.include_router(remediation_router)

    application.add_event_handler("startup", _preload_resources)
    application.add_exception_handler(Exception, _generic_exception_handler)
    return application


app = create_app()
