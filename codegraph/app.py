from __future__ import annotations

import logging
import os
import uuid
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from api.routers.health import router as health_router
from api.routers.policy import router as policy_router
from api.routers.remediation import router as remediation_router
from api.routers.search import router as search_router
from api.routers.upload import router as upload_router

LOGGER = logging.getLogger("codegraph.app")

REQUEST_ID_HEADER = "X-Request-Id"


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
        format="%(asctime)s %(levelname)s [%(name)s] [%(otel_trace_id)s/%(otel_span_id)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def _load_startup_dependencies() -> dict[str, Any]:
    from codegraph.config import settings, validate_runtime_settings
    from codegraph.ingestion.service import ingest
    from codegraph.search.hybrid import load_embedding_model, load_faiss_index, load_signature_map

    validate_runtime_settings()

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


@asynccontextmanager
async def _lifespan(application: FastAPI):
    await _preload_resources(application)
    try:
        yield
    finally:
        from codegraph.db import close_shared_neo4j_driver

        close_shared_neo4j_driver()


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Stamp every request with a stable ``X-Request-Id``.

    Honors an inbound header if present; otherwise generates a UUID4 hex.
    The id is stashed on ``request.state.request_id`` and echoed in the
    response header so clients and server logs can be correlated.
    """

    async def dispatch(self, request: Request, call_next):
        incoming = request.headers.get(REQUEST_ID_HEADER)
        request_id = incoming.strip() if isinstance(incoming, str) and incoming.strip() else uuid.uuid4().hex
        request.state.request_id = request_id
        response = await call_next(request)
        response.headers[REQUEST_ID_HEADER] = request_id
        return response


def _request_id_from(request: Request) -> str:
    """Return the middleware-stamped id, generating a fallback if absent."""
    rid = getattr(getattr(request, "state", None), "request_id", None)
    if isinstance(rid, str) and rid:
        return rid
    return uuid.uuid4().hex


async def _generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Return ``{"error": "internal", "request_id": ...}`` with status 500.

    The full traceback is logged server-side keyed by request_id; the
    client envelope deliberately omits exception messages, internal
    paths, and stack frames.
    """
    request_id = _request_id_from(request)
    LOGGER.exception(
        "Unhandled error on %s (request_id=%s): %s",
        request.url.path,
        request_id,
        exc.__class__.__name__,
    )
    return JSONResponse(
        status_code=500,
        content={"error": "internal", "request_id": request_id},
        headers={REQUEST_ID_HEADER: request_id},
    )


def create_app() -> FastAPI:
    _configure_runtime()
    from codegraph.config import settings
    from codegraph.telemetry import configure_telemetry, install_log_correlation

    configure_telemetry()
    install_log_correlation()

    # DEBUG, not INFO: connection target shouldn't sit in default stdout
    # logs where it gets ingested by aggregators with broader access.
    LOGGER.debug("Runtime Neo4j target: uri=%s user=%s", settings.neo4j_uri, settings.neo4j_user)

    application = FastAPI(lifespan=_lifespan)
    application.state.startup_status = _default_startup_status()

    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor  # noqa: PLC0415

        FastAPIInstrumentor().instrument_app(application)
    except Exception:
        pass

    # Stamp request_id before CORS so it appears in downstream logs.
    application.add_middleware(RequestIDMiddleware)
    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=[REQUEST_ID_HEADER],
    )

    application.include_router(upload_router)
    application.include_router(health_router)
    application.include_router(search_router)
    application.include_router(policy_router)
    application.include_router(remediation_router)

    application.add_exception_handler(Exception, _generic_exception_handler)
    return application


app = create_app()
