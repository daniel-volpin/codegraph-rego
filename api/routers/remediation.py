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


@router.post("/remediation/preview", response_model=RemediationPreviewResponse)
async def remediation_preview(payload: RemediationPreviewRequest):
    # F08: preview_virtual_remediation calls Neo4j, the LLM HTTP endpoint,
    # and OPA via subprocess — all synchronous. Hop to a worker thread.
    result = await asyncio.to_thread(
        preview_virtual_remediation,
        payload.violation_id,
        target_method=payload.target_method,
        file_path=payload.file_path,
    )
    status = (result.get("status") or "").upper()
    if status in {"INVALID"}:
        return JSONResponse(result, status_code=400)
    if status in {"NOT_FOUND"}:
        return JSONResponse(result, status_code=404)
    if status in {"ERROR", "GENERATION_ERROR", "REPLACEMENT_ERROR", "BUILD_ERROR", "VERIFICATION_ERROR"}:
        return JSONResponse(result, status_code=500)
    return JSONResponse(result, status_code=200)


@router.post("/remediation/apply", response_model=RemediationApplyResponse)
async def remediation_apply(payload: RemediationApplyRequest):
    # F08: apply_remediation drives the whole patch/build/verify loop —
    # Neo4j, LLM, OPA, mvn build. All synchronous; run off the event loop.
    result = await asyncio.to_thread(
        apply_remediation,
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
    if status in {"ERROR", "GENERATION_ERROR", "REPLACEMENT_ERROR", "BUILD_ERROR", "VERIFICATION_ERROR"}:
        return JSONResponse(result, status_code=500)
    return JSONResponse(result, status_code=200)
