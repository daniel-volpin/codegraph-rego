from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from api.models.validation import (
    RemediationApplyRequest,
    RemediationApplyResponse,
    RemediationPreviewRequest,
    RemediationPreviewResponse,
)
from codegraph.remediation.orchestration import (
    apply_remediation,
    preview_virtual_remediation,
)

router = APIRouter()
LOGGER = logging.getLogger("codegraph.api.routers.remediation")

_SERVER_ERROR_STATUSES = {
    "ERROR",
    "GENERATION_ERROR",
    "REPLACEMENT_ERROR",
    "BUILD_ERROR",
    "VERIFICATION_ERROR",
}


def _http_status_for_result(result: dict) -> int:
    """Map a remediation result ``status`` to an HTTP status code."""
    status = (result.get("status") or "").upper()
    if status == "INVALID":
        return 400
    if status == "NOT_FOUND":
        return 404
    if status in _SERVER_ERROR_STATUSES:
        return 500
    return 200


@router.post("/remediation/preview", response_model=RemediationPreviewResponse)
async def remediation_preview(payload: RemediationPreviewRequest):
    result = await asyncio.to_thread(
        preview_virtual_remediation,
        payload.violation_id,
        method_key=payload.method_key,
        file_path=payload.file_path,
    )
    return JSONResponse(result, status_code=_http_status_for_result(result))


@router.post("/remediation/apply", response_model=RemediationApplyResponse)
async def remediation_apply(payload: RemediationApplyRequest):
    result = await asyncio.to_thread(
        apply_remediation,
        payload.violation_id,
        method_key=payload.method_key,
        file_path=payload.file_path,
        mode=payload.mode,
        max_attempts=payload.max_attempts,
    )
    return JSONResponse(result, status_code=_http_status_for_result(result))
