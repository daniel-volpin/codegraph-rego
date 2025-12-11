from __future__ import annotations

import logging

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from api.models.validation import (
    RemediationRequest,
    RemediationResponse,
    RemediationRunRequest,
    RemediationRunResponse,
)
from codegraph.api.services.remediation_service import (
    orchestrate_remediation,
    start_remediation_run,
    get_remediation_run,
)

router = APIRouter()
LOGGER = logging.getLogger("codegraph.api.routers.remediation")


@router.post("/remediation/fix", response_model=RemediationResponse)
async def remediation_fix(payload: RemediationRequest):
    try:
        result = orchestrate_remediation(payload.violation_id)
        status = (result.get("status") or "").upper()
        http_status = 200 if status == "VERIFIED" else 400
        if status in {"ERROR", "NOT_FOUND"}:
            http_status = 404 if status == "NOT_FOUND" else 500
        return JSONResponse(result, status_code=http_status)
    except Exception as exc:  # pragma: no cover - runtime guard
        LOGGER.error("Remediation orchestration failed: %s", exc)
        return JSONResponse(
            {"status": "ERROR", "error": str(exc)},
            status_code=500,
        )


@router.post("/remediation/run", response_model=RemediationRunResponse)
async def remediation_run(payload: RemediationRunRequest):
    result = start_remediation_run(
        payload.violation_id,
        max_attempts=payload.max_attempts or 3,
        target_method=payload.target_method,
        file_path=payload.file_path,
        skip_compile=payload.skip_compile,
    )
    if result.get("status") == "INVALID":
        return JSONResponse(result, status_code=400)
    if result.get("status") == "ERROR":
        return JSONResponse(result, status_code=500)
    return JSONResponse(result, status_code=200)


@router.get("/remediation/run/{run_id}", response_model=RemediationRunResponse)
async def remediation_run_status(run_id: str):
    result = get_remediation_run(run_id)
    if result.get("status") == "NOT_FOUND":
        return JSONResponse(result, status_code=404)
    if result.get("status") == "INVALID":
        return JSONResponse(result, status_code=400)
    return JSONResponse(result, status_code=200)
