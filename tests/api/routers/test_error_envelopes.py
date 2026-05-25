from __future__ import annotations

from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.routers.policy import router as policy_router
from api.routers.search import router as search_router
from codegraph.app import REQUEST_ID_HEADER, RequestIDMiddleware, _generic_exception_handler


def _build_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(RequestIDMiddleware)
    app.add_exception_handler(Exception, _generic_exception_handler)
    app.include_router(search_router)
    app.include_router(policy_router)
    return app


def test_search_500_uses_sanitized_envelope() -> None:
    client = TestClient(_build_app(), raise_server_exceptions=False)

    with patch("api.routers.search.run_search", side_effect=RuntimeError("search secret")):
        response = client.post("/search", json={"query": "needle"})

    assert response.status_code == 500
    payload = response.json()
    assert payload["error"] == "internal"
    assert "search secret" not in response.text
    assert payload["request_id"] == response.headers[REQUEST_ID_HEADER]


def test_policy_catalog_500_uses_sanitized_envelope() -> None:
    client = TestClient(_build_app(), raise_server_exceptions=False)

    with patch("api.routers.policy.get_policy_catalog_payload", side_effect=RuntimeError("catalog secret")):
        response = client.get("/policy/catalog")

    assert response.status_code == 500
    payload = response.json()
    assert payload["error"] == "internal"
    assert "catalog secret" not in response.text
    assert payload["request_id"] == response.headers[REQUEST_ID_HEADER]
