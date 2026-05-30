"""Per-request upload progress tracking.

Progress slots are keyed by ``request_id`` (UUID4 hex returned to the
client from ``POST /upload``). ``update_progress`` and its siblings
resolve the target slot via a ``contextvars.ContextVar`` set on
``start_progress``; that context variable survives ``asyncio.to_thread``
(PEP 567), so sync progress callbacks invoked from a worker thread
land on the correct slot without threading a request_id through every
caller.

``get_progress(request_id=None)`` falls back to the latest-started job
so callers that don't yet send a request_id still observe a meaningful
state. The job map is FIFO-capped at ``_MAX_TRACKED_JOBS``.
"""

from __future__ import annotations

import contextvars
import uuid
from collections import OrderedDict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from threading import Lock
from typing import Any, Callable, Dict, Optional


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


_MAX_TRACKED_JOBS = 64
_states: "OrderedDict[str, ProgressState]" = OrderedDict()
_lock = Lock()
_latest_request_id: Optional[str] = None
_current_request_id: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "codegraph_progress_request_id", default=None
)

# State-change listeners are notified after every progress mutation so the
# SSE stream can wake immediately instead of polling on a timer. Listeners
# are called from whichever thread mutated state, so listener callbacks
# must be thread-safe (typically they hand off via
# `loop.call_soon_threadsafe`).
_StateChangeListener = Callable[[Optional[str]], None]
_listeners: "list[_StateChangeListener]" = []
_listeners_lock = Lock()


def register_state_change_listener(listener: _StateChangeListener) -> Callable[[], None]:
    """Register a callback that fires after every progress mutation.

    The callback receives the request_id whose slot changed (or None when
    `_resolve_request_id` itself was unable to settle on a slot). Returns
    an unregister function — call it from the listener's owning scope's
    cleanup path so the listener list cannot grow unboundedly.
    """
    with _listeners_lock:
        _listeners.append(listener)

    def _unregister() -> None:
        with _listeners_lock:
            try:
                _listeners.remove(listener)
            except ValueError:
                pass

    return _unregister


def _notify(changed_rid: Optional[str]) -> None:
    """Fan out to all registered listeners. Exceptions are isolated so one
    misbehaving listener cannot starve the others or leak through to the
    progress writer.
    """
    with _listeners_lock:
        snapshot = list(_listeners)
    for cb in snapshot:
        try:
            cb(changed_rid)
        except Exception:  # pragma: no cover - listener safety net
            pass


def _idle_state() -> ProgressState:
    return ProgressState()


def _resolve_request_id(explicit: Optional[str]) -> Optional[str]:
    if explicit is not None:
        return explicit
    rid = _current_request_id.get()
    if rid is not None:
        return rid
    return _latest_request_id


def _trim_locked() -> None:
    while len(_states) > _MAX_TRACKED_JOBS:
        _states.popitem(last=False)


def start_progress(
    phase: str = "upload",
    message: str = "Starting",
    progress: float = 0.0,
    *,
    request_id: Optional[str] = None,
) -> str:
    """Allocate a new progress slot and return its ``request_id``."""
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
    _notify(rid)
    return rid


def update_progress(phase: str, message: str, progress: float) -> None:
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
    _notify(rid)


def complete_progress(message: str = "Completed") -> None:
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
    _notify(rid)


def error_progress(message: str) -> None:
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
    _notify(rid)


def get_progress(*, request_id: Optional[str] = None) -> Dict[str, Any]:
    rid = _resolve_request_id(request_id)
    with _lock:
        if rid is None:
            return _idle_state().to_dict()
        state = _states.get(rid)
        if state is None:
            return _idle_state().to_dict()
        return state.to_dict()


def reset_progress() -> None:
    global _latest_request_id
    with _lock:
        _states.clear()
        _latest_request_id = None
    _current_request_id.set(None)
