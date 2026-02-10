from __future__ import annotations

import logging

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from api.models.validation import (
    RemediationApplyRequest,
    RemediationApplyResponse,
    RemediationPreviewRequest,
    RemediationPreviewResponse,
)
from codegraph.api.services.remediation_service import (
    apply_remediation,
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


@router.post("/remediation/apply", response_model=RemediationApplyResponse)
async def remediation_apply(payload: RemediationApplyRequest):
    result = apply_remediation(
        payload.violation_id,
        target_method=payload.target_method,
        file_path=payload.file_path,
        mode=payload.mode,
        max_attempts=payload.max_attempts,
    )
    status = (result.get("status") or "").upper()
    if status in {"INVALID"}:
        return JSONResponse(result, status_code=400)
    if status in {"NOT_FOUND"}:
        return JSONResponse(result, status_code=404)
    if status in {"ERROR"}:
        return JSONResponse(result, status_code=500)
    return JSONResponse(result, status_code=200)
