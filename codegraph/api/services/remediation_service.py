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


def preview_virtual_remediation(
    violation_id: str,
    *,
    target_method: str | None = None,
    file_path: str | None = None,
) -> Dict[str, Any]:
    """Public API wrapper for the thesis virtual remediation preview."""
    if not violation_id:
        return {
            "status": "INVALID",
            "error": "violation_id is required",
            "violation_id": violation_id,
        }
    service = _get_service()
    try:
        return service.preview_virtual_fix(violation_id, target_method=target_method, file_path=file_path)
    except Exception as exc:  # pragma: no cover - runtime guard
        LOGGER.exception("Virtual remediation preview failed: %s", exc)
        return {"status": "ERROR", "error": str(exc), "violation_id": violation_id}


def apply_remediation(
    violation_id: str,
    *,
    target_method: str | None = None,
    file_path: str | None = None,
    mode: str = "dry_run",
    max_attempts: int = 2,
    raw_capture_dir: str | None = None,
) -> Dict[str, Any]:
    """Apply remediation in a temp workspace and verify via OPA."""
    if not violation_id:
        return {
            "status": "INVALID",
            "error": "violation_id is required",
            "violation_id": violation_id,
        }
    service = _get_service()
    try:
        return service.apply_fix(
            violation_id,
            target_method=target_method,
            file_path=file_path,
            mode=mode,
            max_attempts=max_attempts,
            raw_capture_dir=raw_capture_dir,
        )
    except Exception as exc:  # pragma: no cover - runtime guard
        LOGGER.exception("Remediation apply failed: %s", exc)
        return {"status": "ERROR", "error": str(exc), "violation_id": violation_id}
