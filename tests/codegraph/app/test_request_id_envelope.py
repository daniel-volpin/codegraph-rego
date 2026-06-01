"""Sanitized error envelope + ``X-Request-Id`` middleware contract.

* Every request gets a stable request_id (UUID4 hex by default;
  honors an inbound ``X-Request-Id`` if present).
* The id is echoed in the response header.
* Unhandled exceptions return ``{"error": "internal", "request_id": ...}``,
  never the raw exception message or stack trace.
* The server-side log records the request_id for correlation.
"""

from __future__ import annotations

import logging
import re
import unittest

from fastapi import APIRouter, FastAPI
from fastapi.testclient import TestClient

from codegraph.app import (
    REQUEST_ID_HEADER,
    RequestIDMiddleware,
    _generic_exception_handler,
)

_UUID_HEX_RE = re.compile(r"^[0-9a-f]{32}$")


def _build_test_app() -> FastAPI:
    """Minimal FastAPI app wired with the middleware + handler under test.

    We don't use ``create_app()`` here because that bootstraps Neo4j, FAISS,
    and the embedding model; this contract is independent of those.
    """
    app = FastAPI()
    app.add_middleware(RequestIDMiddleware)
    app.add_exception_handler(Exception, _generic_exception_handler)

    router = APIRouter()

    @router.get("/_test/ok")
    async def _ok():
        return {"ok": True}

    @router.get("/_test/boom")
    async def _boom():
        raise RuntimeError("boom: should-never-leak-this-secret")

    app.include_router(router)
    return app


class RequestIdMiddlewareTests(unittest.TestCase):
    def test_response_carries_request_id_header(self) -> None:
        client = TestClient(_build_test_app())

        response = client.get("/_test/ok")

        self.assertEqual(response.status_code, 200)
        self.assertIn(REQUEST_ID_HEADER, response.headers)
        self.assertRegex(response.headers[REQUEST_ID_HEADER], _UUID_HEX_RE)

    def test_inbound_request_id_is_echoed_back(self) -> None:
        client = TestClient(_build_test_app())
        inbound = "trace-from-upstream-1234567890"

        response = client.get("/_test/ok", headers={REQUEST_ID_HEADER: inbound})

        self.assertEqual(response.headers[REQUEST_ID_HEADER], inbound)

    def test_each_request_gets_a_unique_id(self) -> None:
        client = TestClient(_build_test_app())

        ids = {client.get("/_test/ok").headers[REQUEST_ID_HEADER] for _ in range(5)}

        self.assertEqual(len(ids), 5)


class SanitizedErrorEnvelopeTests(unittest.TestCase):
    def test_unhandled_exception_returns_sanitized_envelope(self) -> None:
        client = TestClient(_build_test_app(), raise_server_exceptions=False)

        response = client.get("/_test/boom")

        self.assertEqual(response.status_code, 500)
        payload = response.json()
        self.assertEqual(payload["error"], "internal")
        # request_id is a UUID4 hex string and is also present in the header.
        self.assertRegex(payload["request_id"], _UUID_HEX_RE)
        self.assertEqual(payload["request_id"], response.headers[REQUEST_ID_HEADER])

    def test_exception_message_is_not_leaked_to_client(self) -> None:
        client = TestClient(_build_test_app(), raise_server_exceptions=False)

        response = client.get("/_test/boom")

        body = response.text
        # The secret string from the raised RuntimeError must NEVER appear
        # in the client-visible body or headers.
        self.assertNotIn("should-never-leak-this-secret", body)
        self.assertNotIn("RuntimeError", body)
        self.assertNotIn("Traceback", body)
        for header_value in response.headers.values():
            self.assertNotIn("should-never-leak-this-secret", header_value)

    def test_inbound_request_id_propagates_through_error_envelope(self) -> None:
        client = TestClient(_build_test_app(), raise_server_exceptions=False)
        inbound = "operator-supplied-correlation-id"

        response = client.get("/_test/boom", headers={REQUEST_ID_HEADER: inbound})

        self.assertEqual(response.json()["request_id"], inbound)
        self.assertEqual(response.headers[REQUEST_ID_HEADER], inbound)

    def test_server_log_records_request_id_for_correlation(self) -> None:
        client = TestClient(_build_test_app(), raise_server_exceptions=False)
        inbound = "audit-trail-12345"

        with self.assertLogs("codegraph.app", level=logging.ERROR) as log_capture:
            client.get("/_test/boom", headers={REQUEST_ID_HEADER: inbound})

        combined = "\n".join(log_capture.output)
        self.assertIn(inbound, combined)
        # The server-side log records the exception class (for triage) but
        # the client envelope must not.
        self.assertIn("RuntimeError", combined)


if __name__ == "__main__":
    unittest.main()
