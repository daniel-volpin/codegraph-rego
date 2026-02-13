from fastapi import APIRouter
from fastapi.responses import JSONResponse
from codegraph.db import get_neo4j_driver
from codegraph.config import FAISS_INDEX_PATH, SIGNATURE_MAP_PATH, SIGNATURE_MAP_PATH_FULL, EMBEDDING_MODEL_NAME
from api.models.validation import HealthCheckResponse
import shutil
from typing import Any

router = APIRouter()


@router.get("/health", response_model=HealthCheckResponse)
async def health():
    checks: dict[str, Any] = {
        "neo4j": False,
        "faiss_index": False,
        "signature_map": False,
        "embedding_model": False,
        "opa": False,
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
    try:
        if shutil.which("opa"):
            checks["opa"] = True
    except Exception:
        pass
    status = 200 if all([checks["neo4j"], checks["faiss_index"], checks["signature_map"]]) else 503
    return JSONResponse(checks, status_code=status)
