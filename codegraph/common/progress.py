from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from threading import Lock
from typing import Any, Dict, Optional


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ProgressState:
    phase: str = "idle"
    message: str = "Idle"
    progress: float = 0.0
    complete: bool = True
    error: Optional[str] = None
    updated_at: str = field(default_factory=_now)
    started_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


_state = ProgressState()
_lock = Lock()


def start_progress(phase: str = "upload", message: str = "Starting", progress: float = 0.0) -> None:
    """Reset the tracker and mark a new job in progress."""
    normalized = max(0.0, min(progress, 100.0))
    with _lock:
        _state.phase = phase
        _state.message = message
        _state.progress = normalized
        _state.complete = False
        _state.error = None
        timestamp = _now()
        _state.started_at = timestamp
        _state.updated_at = timestamp


def update_progress(phase: str, message: str, progress: float) -> None:
    """Update progress information for the ongoing job."""
    normalized = max(0.0, min(progress, 100.0))
    with _lock:
        _state.phase = phase
        _state.message = message
        _state.progress = normalized
        _state.updated_at = _now()


def complete_progress(message: str = "Completed") -> None:
    """Mark the current job as completed successfully."""
    with _lock:
        _state.phase = "complete"
        _state.message = message
        _state.progress = 100.0
        _state.complete = True
        _state.updated_at = _now()


def error_progress(message: str) -> None:
    """Mark the current job as completed with error information."""
    with _lock:
        _state.phase = "error"
        _state.message = message
        _state.progress = 100.0
        _state.error = message
        _state.complete = True
        _state.updated_at = _now()


def get_progress() -> Dict[str, Any]:
    """Return a snapshot of the current progress state."""
    with _lock:
        return _state.to_dict()


def reset_progress() -> None:
    """Reset the tracker back to its idle state."""
    with _lock:
        _state.phase = "idle"
        _state.message = "Idle"
        _state.progress = 0.0
        _state.complete = True
        _state.error = None
        _state.started_at = None
        _state.updated_at = _now()
