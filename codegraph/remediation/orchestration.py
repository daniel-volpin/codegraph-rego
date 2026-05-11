from __future__ import annotations

import logging
from functools import lru_cache
from typing import Any

from codegraph.remediation.service import RemediationService

LOGGER = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def _get_service() -> RemediationService:
    """Process-wide singleton; tests can reset it via ``cache_clear()``."""
    return RemediationService()


def preview_virtual_remediation(
    violation_id: str,
    *,
    target_method: str | None = None,
    file_path: str | None = None,
) -> dict[str, Any]:
    """Public orchestration wrapper for virtual remediation preview."""
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
    build_command: str | None = None,
    prompt_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
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
            build_command=build_command,
            prompt_context=prompt_context,
        )
    except Exception as exc:  # pragma: no cover - runtime guard
        LOGGER.exception("Remediation apply failed: %s", exc)
        return {"status": "ERROR", "error": str(exc), "violation_id": violation_id}
