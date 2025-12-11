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
        return service.preview_virtual_fix(
            violation_id, target_method=target_method, file_path=file_path
        )
    except Exception as exc:  # pragma: no cover - runtime guard
        LOGGER.exception("Virtual remediation preview failed: %s", exc)
        return {"status": "ERROR", "error": str(exc), "violation_id": violation_id}
