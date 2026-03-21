from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from codegraph.db import get_neo4j_driver
from api.models.validation import HealthCheckResponse
import shutil
from typing import Any

router = APIRouter()


def _load_search_health_dependencies() -> dict[str, Any]:
    from codegraph.config import settings
    from codegraph.search.hybrid import load_faiss_index, load_signature_map, load_embedding_model

    return {
        "faiss_index_path": settings.faiss_index_path,
        "signature_map_path": settings.signature_map_path,
        "signature_map_path_full": settings.signature_map_path_full,
        "embedding_model_name": settings.embedding_model_name,
        "load_faiss_index": load_faiss_index,
        "load_signature_map": load_signature_map,
        "load_embedding_model": load_embedding_model,
    }


@router.get("/health", response_model=HealthCheckResponse)
async def health(request: Request):
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
    return JSONResponse(checks, status_code=200 if core_healthy else 503)
