"""Per-request upload progress tracking (F13).

Pre-F13 this module held a single module-global ``ProgressState``: two
concurrent uploads silently overwrote each other and the frontend
progress bar told a fictional story. F13 keys progress by ``request_id``
(UUID4 hex returned to the client from ``POST /upload``) so each upload
gets an isolated slot.

The public API is intentionally backwards-compatible:

* ``start_progress(...)`` returns the new ``request_id`` (callers that
  ignored the return value pre-F13 keep working; the back-compat shim
  on ``GET /upload/status`` returns the latest job's state when no
  request_id is supplied).
* ``update_progress / complete_progress / error_progress`` take no
  ``request_id`` argument and implicitly target the *current* request
  via a ``contextvars.ContextVar``. This is what lets sync progress
  callbacks deep inside ``_ingest_java_roots`` (running on a worker
  thread via ``asyncio.to_thread``) target the right slot — context
  vars propagate across ``asyncio.to_thread`` since Python 3.9.
* ``get_progress(request_id=None)`` returns the named state, falling
  back to the latest job when ``request_id`` is ``None``.

The job map is FIFO-capped at ``_MAX_TRACKED_JOBS`` so a long-running
process does not accumulate state forever.
"""

from __future__ import annotations

import contextvars
import uuid
from collections import OrderedDict
from dataclasses import asdict, dataclass, field
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
    request_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# F13: per-request state map, FIFO-ordered for bounded memory.
_MAX_TRACKED_JOBS = 64
_states: "OrderedDict[str, ProgressState]" = OrderedDict()
_lock = Lock()
_latest_request_id: Optional[str] = None

# F13: the "current" request id for the handler in flight. Context vars
# survive ``asyncio.to_thread`` (PEP 567 + Python 3.9+), so progress
# callbacks invoked deep in a worker thread automatically target the
# right slot without threading a request_id parameter through every
# layer.
_current_request_id: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "codegraph_progress_request_id", default=None
)


def _idle_state() -> ProgressState:
    return ProgressState(
        phase="idle",
        message="Idle",
        progress=0.0,
        complete=True,
        error=None,
        started_at=None,
        request_id=None,
    )


def _resolve_request_id(explicit: Optional[str]) -> Optional[str]:
    if explicit is not None:
        return explicit
    rid = _current_request_id.get()
    if rid is not None:
        return rid
    return _latest_request_id


def _trim_locked() -> None:
    """Evict oldest entries while ``_states`` exceeds ``_MAX_TRACKED_JOBS``.

    Caller must hold ``_lock``.
    """
    while len(_states) > _MAX_TRACKED_JOBS:
        _states.popitem(last=False)


def start_progress(
    phase: str = "upload",
    message: str = "Starting",
    progress: float = 0.0,
    *,
    request_id: Optional[str] = None,
) -> str:
    """Allocate a new progress slot and return its ``request_id``.

    Callers are expected to capture the returned ``request_id`` and
    surface it to the client (e.g. on the upload response). Pre-F13
    callers that discarded the return value still work — concurrent
    state is no longer overwritten, just no longer addressable by
    those callers.
    """
    global _latest_request_id
    normalized = max(0.0, min(progress, 100.0))
    rid = request_id or uuid.uuid4().hex
    timestamp = _now()
    with _lock:
        _states[rid] = ProgressState(
            phase=phase,
            message=message,
            progress=normalized,
            complete=False,
            error=None,
            started_at=timestamp,
            updated_at=timestamp,
            request_id=rid,
        )
        _states.move_to_end(rid)
        _trim_locked()
        _latest_request_id = rid
    _current_request_id.set(rid)
    return rid


def update_progress(phase: str, message: str, progress: float) -> None:
    """Update the in-flight progress slot resolved from the context var.

    Falls back to the latest-started job if no context var is set
    (covers legacy callers that didn't go through ``start_progress``).
    """
    normalized = max(0.0, min(progress, 100.0))
    rid = _resolve_request_id(None)
    if rid is None:
        return
    with _lock:
        state = _states.get(rid)
        if state is None:
            return
        state.phase = phase
        state.message = message
        state.progress = normalized
        state.updated_at = _now()


def complete_progress(message: str = "Completed") -> None:
    """Mark the in-flight slot as successfully completed."""
    rid = _resolve_request_id(None)
    if rid is None:
        return
    with _lock:
        state = _states.get(rid)
        if state is None:
            return
        state.phase = "complete"
        state.message = message
        state.progress = 100.0
        state.complete = True
        state.error = None
        state.updated_at = _now()


def error_progress(message: str) -> None:
    """Mark the in-flight slot as completed with an error."""
    rid = _resolve_request_id(None)
    if rid is None:
        return
    with _lock:
        state = _states.get(rid)
        if state is None:
            return
        state.phase = "error"
        state.message = message
        state.progress = 100.0
        state.error = message
        state.complete = True
        state.updated_at = _now()


def get_progress(*, request_id: Optional[str] = None) -> Dict[str, Any]:
    """Return a snapshot of the progress state for ``request_id``.

    When ``request_id`` is ``None``, returns the latest-started job's
    state — the back-compat shim that keeps ``GET /upload/status``
    (no query string) returning meaningful data for clients that don't
    yet send a request_id.

    When no job has ever started, returns an idle-state snapshot
    (matches the pre-F13 default-construction behavior).
    """
    rid = _resolve_request_id(request_id)
    with _lock:
        if rid is None:
            return _idle_state().to_dict()
        state = _states.get(rid)
        if state is None:
            return _idle_state().to_dict()
        return state.to_dict()


def reset_progress() -> None:
    """Forget every tracked job and clear the latest pointer.

    Test helper; never invoked from production code.
    """
    global _latest_request_id
    with _lock:
        _states.clear()
        _latest_request_id = None
    _current_request_id.set(None)
