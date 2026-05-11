from __future__ import annotations

import asyncio
import shutil
import time
from threading import Lock
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from api.models.validation import HealthCheckResponse, LivenessResponse
from codegraph.db import get_neo4j_driver

router = APIRouter()


# 30 s is short enough to surface a degraded dependency quickly and long
# enough that 1 Hz polling doesn't reload FAISS / the embedding model.
_READINESS_TTL_SECONDS = 30.0
_readiness_cache: dict[str, Any] = {"expires_at": 0.0, "payload": None, "status_code": 503}
_readiness_lock = Lock()


def _load_search_health_dependencies() -> dict[str, Any]:
    from codegraph.config import settings
    from codegraph.search.hybrid import load_embedding_model, load_faiss_index, load_signature_map

    return {
        "faiss_index_path": settings.faiss_index_path,
        "signature_map_path": settings.signature_map_path,
        "signature_map_path_full": settings.signature_map_path_full,
        "embedding_model_name": settings.embedding_model_name,
        "load_faiss_index": load_faiss_index,
        "load_signature_map": load_signature_map,
        "load_embedding_model": load_embedding_model,
    }


def _compute_readiness(request: Request) -> tuple[dict[str, Any], int]:
    """Deep readiness probe: actually exercises every dependency.

    This is the legacy ``/health`` body, lifted into a helper so the cached
    ``/readyz`` and the legacy alias share one source of truth. Never raises;
    failures degrade to ``status_code=503`` with structured details.
    """
    startup_state = getattr(request.app.state, "startup_status", None) or {
        "ready": False,
        "phase": "pending",
        "checks": {},
        "errors": {"startup": "startup status unavailable"},
    }
    checks: dict[str, Any] = {
        "status": "degraded",
        "startup_ready": bool(startup_state.get("ready")),
        "neo4j": False,
        "faiss_index": False,
        "signature_map": False,
        "embedding_model": False,
        "opa": False,
        "startup": {
            "ready": bool(startup_state.get("ready")),
            "phase": startup_state.get("phase") or "pending",
            "checks": startup_state.get("checks") or {},
            "errors": startup_state.get("errors") or {},
        },
        "details": {},
    }
    try:
        drv = get_neo4j_driver()
        with drv.session() as s:
            s.run("RETURN 1").consume()
        drv.close()
        checks["neo4j"] = True
    except Exception as e:
        checks["details"]["neo4j"] = str(e)
    try:
        deps = _load_search_health_dependencies()
        deps["load_faiss_index"](deps["faiss_index_path"])
        try:
            deps["load_signature_map"](deps["signature_map_path_full"])
        except Exception:
            deps["load_signature_map"](deps["signature_map_path"])
        checks["faiss_index"] = True
        checks["signature_map"] = True
        deps["load_embedding_model"](deps["embedding_model_name"])
        checks["embedding_model"] = True
    except Exception as e:
        checks["details"]["search"] = str(e)
    try:
        if shutil.which("opa"):
            checks["opa"] = True
    except Exception:
        pass
    if checks["startup"]["errors"]:
        checks["details"]["startup"] = checks["startup"]["errors"]
    core_healthy = all(
        [
            checks["startup_ready"],
            checks["neo4j"],
            checks["faiss_index"],
            checks["signature_map"],
            checks["embedding_model"],
            checks["opa"],
        ]
    )
    checks["status"] = "ok" if core_healthy else "degraded"
    return checks, 200 if core_healthy else 503


def _cached_readiness(request: Request) -> tuple[dict[str, Any], int]:
    """Return readiness payload, recomputing only when the TTL has elapsed.

    The cache is process-local and lock-guarded so concurrent ``/readyz``
    requests share one probe rather than fanning out to N FAISS reloads.
    """
    now = time.monotonic()
    with _readiness_lock:
        if _readiness_cache["payload"] is not None and now < _readiness_cache["expires_at"]:
            return _readiness_cache["payload"], _readiness_cache["status_code"]
    # Compute outside the lock so a slow probe doesn't block concurrent /readyz
    # callers that would otherwise still observe a fresh cached value.
    payload, status_code = _compute_readiness(request)
    with _readiness_lock:
        _readiness_cache["payload"] = payload
        _readiness_cache["status_code"] = status_code
        _readiness_cache["expires_at"] = time.monotonic() + _READINESS_TTL_SECONDS
    return payload, status_code


def reset_readiness_cache() -> None:
    """Test helper: clear the readiness cache so the next call recomputes."""
    with _readiness_lock:
        _readiness_cache["payload"] = None
        _readiness_cache["status_code"] = 503
        _readiness_cache["expires_at"] = 0.0


@router.get("/healthz", response_model=LivenessResponse)
async def healthz() -> LivenessResponse:
    """Liveness probe: no external I/O, safe for high-frequency polling."""
    return LivenessResponse(status="alive")


@router.get("/readyz", response_model=HealthCheckResponse)
async def readyz(request: Request):
    """Readiness probe: exercises every runtime dependency, cached 30 s."""
    payload, status_code = await asyncio.to_thread(_cached_readiness, request)
    return JSONResponse(payload, status_code=status_code)


@router.get("/health", response_model=HealthCheckResponse)
async def health(request: Request):
    """Alias of ``/readyz`` retained for pre-existing callers.

    Shares the readiness cache so calling both does not double-probe.
    """
    payload, status_code = await asyncio.to_thread(_cached_readiness, request)
    return JSONResponse(payload, status_code=status_code)
