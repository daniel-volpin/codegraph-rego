from __future__ import annotations

import logging
from typing import Any, Dict

from codegraph.remediation.service import RemediationService

LOGGER = logging.getLogger(__name__)
_SERVICE: RemediationService | None = None


def _get_service() -> RemediationService:
    global _SERVICE
    if _SERVICE is None:
        _SERVICE = RemediationService()
    return _SERVICE


def orchestrate_remediation(violation_id: str) -> Dict[str, Any]:
    if not violation_id:
        return {
            "status": "INVALID",
            "error": "violation_id is required",
        }
    service = _get_service()
    LOGGER.info("Starting remediation loop for violation %s", violation_id)
    result = service.orchestrate_fix(violation_id)
    LOGGER.info(
        "Remediation loop finished for %s with status %s",
        violation_id,
        result.get("status"),
    )
    return result


def start_remediation_run(
    violation_id: str,
    *,
    max_attempts: int = 3,
    target_method: str | None = None,
    file_path: str | None = None,
    skip_compile: bool | None = True,
) -> Dict[str, Any]:
    if not violation_id:
        return {
            "status": "INVALID",
            "error": "violation_id is required",
        }
    service = _get_service()
    try:
        run = service.start_run(
            violation_id,
            max_attempts=max_attempts,
            target_method=target_method,
            file_path=file_path,
            skip_compile=bool(skip_compile),
        )
        return run.to_dict()
    except Exception as exc:
        LOGGER.exception("Failed to start remediation run for %s: %s", violation_id, exc)
        return {"status": "ERROR", "error": str(exc)}


def get_remediation_run(run_id: str) -> Dict[str, Any]:
    if not run_id:
        return {
            "status": "INVALID",
            "error": "run_id is required",
        }
    service = _get_service()
    run = service.get_run(run_id)
    if run is None:
        return {
            "status": "NOT_FOUND",
            "error": f"Remediation run {run_id} not found",
        }
    return run.to_dict()


def preview_virtual_remediation(
    violation_id: str,
    *,
    target_method: str | None = None,
    file_path: str | None = None,
) -> Dict[str, Any]:
    if not violation_id:
        return {
            "status": "INVALID",
            "error": "violation_id is required",
            "violation_id": violation_id,
        }
    service = _get_service()
    try:
        return service.preview_virtual_fix(
            violation_id, target_method=target_method, file_path=file_path
        )
    except Exception as exc:  # pragma: no cover - runtime guard
        LOGGER.exception("Virtual remediation preview failed: %s", exc)
        return {"status": "ERROR", "error": str(exc), "violation_id": violation_id}
