import json
import unittest
from unittest.mock import patch

from fastapi import FastAPI
from starlette.requests import Request


class _FakeResult:
    def consume(self) -> None:
        return None


class _FakeSession:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False

    def run(self, *_args, **_kwargs):
        return _FakeResult()


class _FakeDriver:
    def session(self) -> _FakeSession:
        return _FakeSession()

    def close(self) -> None:
        return None


def _build_request(app: FastAPI) -> Request:
    return Request({"type": "http", "app": app, "headers": []})


class HealthRouterTests(unittest.IsolatedAsyncioTestCase):
    @patch("api.routers.health.shutil.which", return_value="/usr/local/bin/opa")
    @patch("api.routers.health._load_search_health_dependencies")
    @patch("api.routers.health.get_neo4j_driver", return_value=_FakeDriver())
    async def test_health_returns_ok_when_runtime_is_ready(
        self,
        _mock_driver,
        mock_search_deps,
        _mock_which,
    ) -> None:
        from api.routers.health import health

        app = FastAPI()
        app.state.startup_status = {
            "ready": True,
            "phase": "ready",
            "checks": {
                "ingestion": True,
                "signature_map": True,
                "faiss_index": True,
                "embedding_model": True,
            },
            "errors": {},
        }
        mock_search_deps.return_value = {
            "faiss_index_path": "index.faiss",
            "signature_map_path": "sigmap.json",
            "signature_map_path_full": "sigmap_full.json",
            "embedding_model_name": "dummy-model",
            "load_faiss_index": lambda *_args, **_kwargs: None,
            "load_signature_map": lambda *_args, **_kwargs: None,
            "load_embedding_model": lambda *_args, **_kwargs: None,
        }

        response = await health(_build_request(app))

        self.assertEqual(response.status_code, 200)
        payload = json.loads(response.body)
        self.assertEqual(payload["status"], "ok")
        self.assertTrue(payload["startup_ready"])
        self.assertEqual(payload["startup"]["phase"], "ready")

    @patch("api.routers.health.shutil.which", return_value="/usr/local/bin/opa")
    @patch("api.routers.health._load_search_health_dependencies")
    @patch("api.routers.health.get_neo4j_driver", return_value=_FakeDriver())
    async def test_health_returns_degraded_when_startup_is_degraded(
        self,
        _mock_driver,
        mock_search_deps,
        _mock_which,
    ) -> None:
        from api.routers.health import health

        app = FastAPI()
        app.state.startup_status = {
            "ready": False,
            "phase": "degraded",
            "checks": {
                "ingestion": False,
                "signature_map": True,
                "faiss_index": True,
                "embedding_model": True,
            },
            "errors": {"ingestion": "ingest failed"},
        }
        mock_search_deps.return_value = {
            "faiss_index_path": "index.faiss",
            "signature_map_path": "sigmap.json",
            "signature_map_path_full": "sigmap_full.json",
            "embedding_model_name": "dummy-model",
            "load_faiss_index": lambda *_args, **_kwargs: None,
            "load_signature_map": lambda *_args, **_kwargs: None,
            "load_embedding_model": lambda *_args, **_kwargs: None,
        }

        response = await health(_build_request(app))

        self.assertEqual(response.status_code, 503)
        payload = json.loads(response.body)
        self.assertEqual(payload["status"], "degraded")
        self.assertFalse(payload["startup_ready"])
        self.assertEqual(payload["startup"]["errors"]["ingestion"], "ingest failed")
        self.assertEqual(payload["details"]["startup"]["ingestion"], "ingest failed")


if __name__ == "__main__":
    unittest.main()
