from __future__ import annotations

import logging

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from api.models.validation import RemediationRequest, RemediationResponse
from codegraph.api.services.remediation_service import orchestrate_remediation

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
