from __future__ import annotations

import logging
import os
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from api.routers.health import router as health_router
from api.routers.policy import router as policy_router
from api.routers.remediation import router as remediation_router
from api.routers.search import router as search_router
from api.routers.upload import router as upload_router

LOGGER = logging.getLogger("codegraph.app")


def _default_startup_status() -> dict[str, Any]:
    return {
        "ready": False,
        "phase": "pending",
        "checks": {
            "ingestion": False,
            "signature_map": False,
            "faiss_index": False,
            "embedding_model": False,
        },
        "errors": {},
    }


def _configure_runtime() -> None:
    os.environ["TOKENIZERS_PARALLELISM"] = "false"
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def _load_startup_dependencies() -> dict[str, Any]:
    from codegraph.config import settings
    from codegraph.ingestion.service import ingest
    from codegraph.search.hybrid import load_embedding_model, load_faiss_index, load_signature_map

    return {
        "embedding_model_name": settings.embedding_model_name,
        "faiss_index_path": settings.faiss_index_path,
        "java_root_dir": settings.java_root_dir,
        "signature_map_path": settings.signature_map_path,
        "signature_map_path_full": settings.signature_map_path_full,
        "ingest": ingest,
        "load_embedding_model": load_embedding_model,
        "load_faiss_index": load_faiss_index,
        "load_signature_map": load_signature_map,
    }


async def _preload_resources(application: FastAPI) -> None:
    startup_status = _default_startup_status()
    startup_status["phase"] = "running"
    application.state.startup_status = startup_status
    try:
        deps = _load_startup_dependencies()

        LOGGER.info("Starting automatic graph synchronization...")
        try:
            deps["ingest"](deps["java_root_dir"], sync=True)
            startup_status["checks"]["ingestion"] = True
        except Exception as exc:
            LOGGER.error("Startup ingestion failed: %s", exc)
            startup_status["errors"]["ingestion"] = str(exc)

        try:
            deps["load_signature_map"](deps["signature_map_path_full"])
            startup_status["checks"]["signature_map"] = True
        except Exception:
            deps["load_signature_map"](deps["signature_map_path"])
            startup_status["checks"]["signature_map"] = True

        deps["load_faiss_index"](deps["faiss_index_path"])
        startup_status["checks"]["faiss_index"] = True

        deps["load_embedding_model"](deps["embedding_model_name"])
        startup_status["checks"]["embedding_model"] = True
        if all(startup_status["checks"].values()):
            LOGGER.info("Search resources preloaded successfully.")
    except Exception as exc:
        startup_status["errors"]["startup"] = str(exc)
        LOGGER.warning("[startup] Skipping search preload: %s", exc)
    finally:
        startup_status["ready"] = all(startup_status["checks"].values())
        startup_status["phase"] = "ready" if startup_status["ready"] else "degraded"
        if not startup_status["ready"]:
            LOGGER.warning("Application startup completed in degraded mode: %s", startup_status["errors"])
        application.state.startup_status = startup_status


async def _generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    LOGGER.error("Unhandled error on %s: %s", request.url.path, exc)
    return JSONResponse(status_code=500, content={"error": "Internal server error", "details": str(exc)})


def create_app() -> FastAPI:
    _configure_runtime()
    from codegraph.config import CORS_ALLOWED_ORIGINS

    application = FastAPI()
    application.state.startup_status = _default_startup_status()
    application.add_middleware(
        CORSMiddleware,
        allow_origins=CORS_ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    application.include_router(upload_router)
    application.include_router(health_router)
    application.include_router(search_router)
    application.include_router(policy_router)
    application.include_router(remediation_router)

    async def _startup() -> None:
        await _preload_resources(application)

    application.add_event_handler("startup", _startup)
    application.add_exception_handler(Exception, _generic_exception_handler)
    return application


app = create_app()
