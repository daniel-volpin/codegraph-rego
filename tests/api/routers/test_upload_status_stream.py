from __future__ import annotations

import json

from fastapi import FastAPI
from fastapi.testclient import TestClient

import api.routers.upload as upload_module
from api.routers.upload import router as upload_router
from codegraph.common import progress


def _build_app() -> FastAPI:
    app = FastAPI()
    app.include_router(upload_router)
    return app


def _parse_sse_events(body: str) -> list[tuple[str, dict]]:
    """Naively split an SSE body into (event, data-dict) tuples."""
    events: list[tuple[str, dict]] = []
    for block in body.split("\n\n"):
        block = block.strip()
        if not block:
            continue
        event_name = "message"
        data_lines: list[str] = []
        for line in block.split("\n"):
            if line.startswith("event:"):
                event_name = line[len("event:") :].strip()
            elif line.startswith("data:"):
                data_lines.append(line[len("data:") :].strip())
        payload = json.loads("\n".join(data_lines)) if data_lines else {}
        events.append((event_name, payload))
    return events


def test_upload_status_stream_emits_initial_state_and_completion(monkeypatch) -> None:
    # Tight cadence so the test loop finishes in milliseconds.
    monkeypatch.setattr(upload_module, "_SSE_POLL_INTERVAL_S", 0.01)
    monkeypatch.setattr(upload_module, "_SSE_HEARTBEAT_INTERVAL_S", 1.0)
    monkeypatch.setattr(upload_module, "_SSE_TERMINAL_GRACE_S", 0.0)
    progress.reset_progress()
    request_id = progress.start_progress(phase="upload", message="Starting", progress=0.0)

    client = TestClient(_build_app())
    try:
        # In a separate thread, flip the slot to complete shortly after the
        # stream connects so the generator sees a state change → terminal.
        import threading

        def _flip() -> None:
            import time

            time.sleep(0.05)
            progress.complete_progress("Done")

        threading.Thread(target=_flip, daemon=True).start()

        with client.stream("GET", f"/upload/status/stream?request_id={request_id}") as response:
            assert response.status_code == 200
            assert response.headers["content-type"].startswith("text/event-stream")
            assert response.headers["cache-control"] == "no-cache"
            body = "".join(response.iter_text())

        events = _parse_sse_events(body)
        # Must include at least one status event and a terminal complete event.
        assert any(name == "status" for name, _ in events), events
        assert any(name == "complete" for name, _ in events), events
        terminal = next(payload for name, payload in events if name == "complete")
        assert terminal["complete"] is True
        assert terminal["request_id"] == request_id
    finally:
        progress.reset_progress()


def test_upload_status_stream_closes_when_already_complete(monkeypatch) -> None:
    monkeypatch.setattr(upload_module, "_SSE_POLL_INTERVAL_S", 0.01)
    monkeypatch.setattr(upload_module, "_SSE_HEARTBEAT_INTERVAL_S", 1.0)
    monkeypatch.setattr(upload_module, "_SSE_TERMINAL_GRACE_S", 0.0)
    progress.reset_progress()
    request_id = progress.start_progress(phase="upload", message="Starting", progress=0.0)
    progress.complete_progress("Done")

    client = TestClient(_build_app())
    try:
        with client.stream("GET", f"/upload/status/stream?request_id={request_id}") as response:
            assert response.status_code == 200
            body = "".join(response.iter_text())
        events = _parse_sse_events(body)
        # When the job is already complete we expect exactly one status event
        # and one complete event before the stream closes.
        assert [name for name, _ in events] == ["status", "complete"]
    finally:
        progress.reset_progress()
