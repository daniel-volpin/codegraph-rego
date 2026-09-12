from __future__ import annotations

import logging
from functools import lru_cache
from typing import Any

from codegraph.config import settings
from codegraph.remediation.agentic import AgenticRemediationService
from codegraph.remediation.service import RemediationService

LOGGER = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def _get_service() -> RemediationService:
    """Process-wide singleton; tests can reset it via ``cache_clear()``."""
    return RemediationService()


def preview_virtual_remediation(
    violation_id: str,
    *,
    method_key: str,
    file_path: str | None = None,
) -> dict[str, Any]:
    """Public orchestration wrapper for virtual remediation preview."""
    if not violation_id:
        return {
            "status": "INVALID",
            "error": "violation_id is required",
            "violation_id": violation_id,
        }
    if not method_key:
        return {
            "status": "INVALID",
            "error": "method_key is required",
            "violation_id": violation_id,
        }
    service = _get_service()
    try:
        return service.preview_virtual_fix(violation_id, method_key=method_key, file_path=file_path)
    except Exception as exc:  # pragma: no cover - runtime guard
        LOGGER.exception(
            "Virtual remediation preview failed",
            extra={"err": str(exc), "err_type": type(exc).__name__, "violation_id": violation_id},
        )
        return {"status": "ERROR", "error": str(exc), "violation_id": violation_id}


def apply_remediation(
    violation_id: str,
    *,
    method_key: str,
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
    if not method_key:
        return {
            "status": "INVALID",
            "error": "method_key is required",
            "violation_id": violation_id,
        }
    service = _get_service()
    try:
        return service.apply_fix(
            violation_id,
            method_key=method_key,
            file_path=file_path,
            mode=mode,
            max_attempts=max_attempts,
            raw_capture_dir=raw_capture_dir,
            build_command=build_command,
            prompt_context=prompt_context,
        )
    except Exception as exc:  # pragma: no cover - runtime guard
        LOGGER.exception(
            "Remediation apply failed",
            extra={"err": str(exc), "err_type": type(exc).__name__, "violation_id": violation_id},
        )
        return {"status": "ERROR", "error": str(exc), "violation_id": violation_id}


def run_agentic_remediation(
    finding: dict[str, Any],
    *,
    workspace_root: str | None = None,
    max_turns: int = 15,
    model: str | None = None,
) -> dict[str, Any]:
    """Public orchestration wrapper for autonomous multi-turn agentic remediation."""
    root = workspace_root or settings.upload_dir
    service = AgenticRemediationService()
    try:
        res = service.remediate_finding(finding, workspace_root=root, max_turns=max_turns, model=model)
        return res.to_dict()
    except Exception as exc:
        LOGGER.exception("Agentic remediation execution failed", extra={"err": str(exc)})
        return {"status": "ERROR", "error": str(exc)}
