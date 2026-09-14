"""A degraded startup verdict is re-probed, not trusted until restart.

The verdict is computed once during lifespan startup. Ingesting a codebase or
rebuilding the index can make a degraded process ready, and before this the
answer stayed "degraded" until someone restarted the server — right after an
upload had reported success.
"""

from __future__ import annotations

import unittest

from fastapi import FastAPI, Request

from api.routers.health import _current_startup_state

_DEGRADED = {
    "ready": False,
    "phase": "degraded",
    "checks": {"graph_generation": False},
    "errors": {"startup": "Active retrieval artifact is stale"},
}
_READY = {"ready": True, "phase": "ready", "checks": {"graph_generation": True}, "errors": {}}


def _request(app: FastAPI) -> Request:
    return Request({"type": "http", "app": app, "headers": []})


class TestStartupRecheck(unittest.TestCase):
    def test_a_degraded_verdict_is_reprobed(self) -> None:
        app = FastAPI()
        app.state.startup_status = dict(_DEGRADED)
        calls: list[FastAPI] = []

        def refresh(application: FastAPI) -> dict:
            calls.append(application)
            application.state.startup_status = dict(_READY)
            return application.state.startup_status

        app.state.refresh_startup_status = refresh

        state = _current_startup_state(_request(app))

        self.assertTrue(state["ready"])
        self.assertEqual(len(calls), 1)

    def test_a_ready_verdict_is_not_reprobed(self) -> None:
        """Readiness is on the hot path; a healthy process must not re-probe."""
        app = FastAPI()
        app.state.startup_status = dict(_READY)
        app.state.refresh_startup_status = lambda _app: self.fail("should not re-probe")

        self.assertTrue(_current_startup_state(_request(app))["ready"])

    def test_a_failing_probe_keeps_the_previous_verdict(self) -> None:
        app = FastAPI()
        app.state.startup_status = dict(_DEGRADED)

        def refresh(_app: FastAPI) -> dict:
            raise RuntimeError("neo4j down")

        app.state.refresh_startup_status = refresh

        state = _current_startup_state(_request(app))

        self.assertFalse(state["ready"])
        self.assertIn("startup", state["errors"])

    def test_no_hook_is_tolerated(self) -> None:
        app = FastAPI()
        app.state.startup_status = dict(_DEGRADED)

        self.assertFalse(_current_startup_state(_request(app))["ready"])
