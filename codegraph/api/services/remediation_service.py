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
