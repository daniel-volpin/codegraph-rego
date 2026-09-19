from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator

from fastapi import Request

from codegraph.common.progress import (
    get_progress,
    register_state_change_listener,
)


async def upload_status_event_stream(
    request: Request,
    request_id: str | None,
    *,
    heartbeat_interval_provider=lambda: 5.0,
    terminal_grace_provider=lambda: 0.5,
) -> AsyncIterator[bytes]:
    loop = asyncio.get_running_loop()
    state_changed = asyncio.Event()

    def _on_state_change(changed_rid: str | None) -> None:
        if request_id is None or changed_rid == request_id:
            try:
                loop.call_soon_threadsafe(state_changed.set)
            except RuntimeError:
                pass

    unregister = register_state_change_listener(_on_state_change)
    last_payload: str | None = None
    try:
        while True:
            if await request.is_disconnected():
                return
            state_changed.clear()
            state = get_progress(request_id=request_id)
            payload = json.dumps(state, separators=(",", ":"))
            if payload != last_payload:
                yield f"event: status\ndata: {payload}\n\n".encode()
                last_payload = payload
            if state.get("complete"):
                yield f"event: complete\ndata: {payload}\n\n".encode()
                await asyncio.sleep(terminal_grace_provider())
                return
            try:
                await asyncio.wait_for(state_changed.wait(), timeout=heartbeat_interval_provider())
            except TimeoutError:
                yield b": heartbeat\n\n"
    finally:
        unregister()
