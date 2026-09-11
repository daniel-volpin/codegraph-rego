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
from codegraph.config import settings, validate_runtime_settings
from codegraph.db import close_shared_neo4j_driver, shared_neo4j_driver
from codegraph.java.service import JavaParserProtocolError, parse_java_source
from codegraph.search.hybrid import load_embedding_model, validate_retrieval_generation
from codegraph.telemetry import configure_telemetry, install_log_correlation

LOGGER = logging.getLogger("codegraph.app")

REQUEST_ID_HEADER = "X-Request-Id"


def _default_startup_status() -> dict[str, Any]:
    return {
        "ready": False,
        "phase": "pending",
        "checks": {
            "java_parser": False,
            "graph_generation": False,
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
    validate_runtime_settings()

    return {
        "embedding_model_name": settings.embedding_model_name,
        "validate_generation": lambda: validate_retrieval_generation(shared_neo4j_driver()),
        "check_java_parser": _check_java_parser,
        "load_embedding_model": load_embedding_model,
    }


def _check_java_parser() -> None:
    parsed = parse_java_source(
        b"class CodeGraphReadiness {}",
        relative_path="CodeGraphReadiness.java",
        resolve_bindings=False,
    )
    if parsed.coverage != "complete" or len(parsed.types) != 1:
        raise JavaParserProtocolError("Java parser did not analyze the readiness fixture completely.")


async def _preload_resources(application: FastAPI) -> None:
    startup_status = _default_startup_status()
    startup_status["phase"] = "running"
    application.state.startup_status = startup_status
    try:
        deps = _load_startup_dependencies()
        deps["check_java_parser"]()
        startup_status["checks"]["java_parser"] = True

        deps["validate_generation"]()
        startup_status["checks"]["graph_generation"] = True
        startup_status["checks"]["signature_map"] = True
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
