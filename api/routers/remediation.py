from __future__ import annotations

import logging

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from api.models.validation import (
    RemediationPreviewRequest,
    RemediationPreviewResponse,
)
from codegraph.api.services.remediation_service import (
    preview_virtual_remediation,
)

router = APIRouter()
LOGGER = logging.getLogger("codegraph.api.routers.remediation")


@router.post("/remediation/preview", response_model=RemediationPreviewResponse)
async def remediation_preview(payload: RemediationPreviewRequest):
    result = preview_virtual_remediation(
        payload.violation_id,
        target_method=payload.target_method,
        file_path=payload.file_path,
    )
    status = (result.get("status") or "").upper()
    if status in {"INVALID"}:
        return JSONResponse(result, status_code=400)
    if status in {"NOT_FOUND"}:
        return JSONResponse(result, status_code=404)
    if status in {"ERROR"}:
        return JSONResponse(result, status_code=500)
    return JSONResponse(result, status_code=200)
