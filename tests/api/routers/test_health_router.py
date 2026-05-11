import json
import unittest
from unittest.mock import MagicMock, patch

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


def _ready_app() -> FastAPI:
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
    return app


def _degraded_app() -> FastAPI:
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
    return app


def _ready_search_deps() -> dict:
    return {
        "faiss_index_path": "index.faiss",
        "signature_map_path": "sigmap.json",
        "signature_map_path_full": "sigmap_full.json",
        "embedding_model_name": "dummy-model",
        "load_faiss_index": lambda *_args, **_kwargs: None,
        "load_signature_map": lambda *_args, **_kwargs: None,
        "load_embedding_model": lambda *_args, **_kwargs: None,
    }


class HealthRouterTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        # F30: the readiness probe is cached for 30s. Tests must reset the
        # cache so a previous test's outcome doesn't leak into the current one.
        from api.routers.health import reset_readiness_cache

        reset_readiness_cache()

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

        mock_search_deps.return_value = _ready_search_deps()

        response = await health(_build_request(_ready_app()))

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

        mock_search_deps.return_value = _ready_search_deps()

        response = await health(_build_request(_degraded_app()))

        self.assertEqual(response.status_code, 503)
        payload = json.loads(response.body)
        self.assertEqual(payload["status"], "degraded")
        self.assertFalse(payload["startup_ready"])
        self.assertEqual(payload["startup"]["errors"]["ingestion"], "ingest failed")
        self.assertEqual(payload["details"]["startup"]["ingestion"], "ingest failed")


class HealthzLivenessTests(unittest.IsolatedAsyncioTestCase):
    """F30: GET /healthz is a cheap liveness probe with no external I/O."""

    async def test_healthz_returns_200_alive(self) -> None:
        from api.routers.health import healthz

        result = await healthz()

        self.assertEqual(result.status, "alive")

    @patch("api.routers.health.get_neo4j_driver")
    @patch("api.routers.health._load_search_health_dependencies")
    @patch("api.routers.health.shutil.which")
    async def test_healthz_does_no_external_io(
        self,
        mock_which,
        mock_search_deps,
        mock_driver,
    ) -> None:
        from api.routers.health import healthz

        await healthz()

        mock_driver.assert_not_called()
        mock_search_deps.assert_not_called()
        mock_which.assert_not_called()


class ReadyzCachingTests(unittest.IsolatedAsyncioTestCase):
    """F30: GET /readyz exercises every dependency, but caches for 30 seconds."""

    def setUp(self) -> None:
        from api.routers.health import reset_readiness_cache

        reset_readiness_cache()

    @patch("api.routers.health.shutil.which", return_value="/usr/local/bin/opa")
    @patch("api.routers.health._load_search_health_dependencies")
    @patch("api.routers.health.get_neo4j_driver")
    async def test_readyz_reports_dependency_status(
        self,
        mock_driver,
        mock_search_deps,
        _mock_which,
    ) -> None:
        from api.routers.health import readyz

        mock_driver.return_value = _FakeDriver()
        mock_search_deps.return_value = _ready_search_deps()

        response = await readyz(_build_request(_ready_app()))

        self.assertEqual(response.status_code, 200)
        payload = json.loads(response.body)
        self.assertEqual(payload["status"], "ok")

    @patch("api.routers.health.shutil.which", return_value="/usr/local/bin/opa")
    @patch("api.routers.health._load_search_health_dependencies")
    @patch("api.routers.health.get_neo4j_driver")
    async def test_readyz_caches_second_call_within_ttl(
        self,
        mock_driver,
        mock_search_deps,
        _mock_which,
    ) -> None:
        """Second /readyz within the TTL must not re-probe Neo4j or FAISS."""
        from api.routers.health import readyz

        mock_driver.return_value = _FakeDriver()
        # Track FAISS reload calls via a MagicMock so we can count invocations.
        load_faiss = MagicMock(return_value=None)
        load_sig = MagicMock(return_value=None)
        load_embed = MagicMock(return_value=None)
        mock_search_deps.return_value = {
            "faiss_index_path": "index.faiss",
            "signature_map_path": "sigmap.json",
            "signature_map_path_full": "sigmap_full.json",
            "embedding_model_name": "dummy-model",
            "load_faiss_index": load_faiss,
            "load_signature_map": load_sig,
            "load_embedding_model": load_embed,
        }
        app = _ready_app()

        await readyz(_build_request(app))
        await readyz(_build_request(app))
        await readyz(_build_request(app))

        # First call performs one probe each; second and third hit the cache.
        self.assertEqual(load_faiss.call_count, 1)
        self.assertEqual(load_embed.call_count, 1)
        # Neo4j driver fetched exactly once for the same reason.
        self.assertEqual(mock_driver.call_count, 1)

    @patch("api.routers.health.shutil.which", return_value="/usr/local/bin/opa")
    @patch("api.routers.health._load_search_health_dependencies")
    @patch("api.routers.health.get_neo4j_driver", return_value=_FakeDriver())
    async def test_health_and_readyz_share_the_cache(
        self,
        _mock_driver,
        mock_search_deps,
        _mock_which,
    ) -> None:
        """The legacy /health alias and /readyz must hit one shared cache."""
        from api.routers.health import health, readyz

        load_faiss = MagicMock(return_value=None)
        mock_search_deps.return_value = {
            "faiss_index_path": "index.faiss",
            "signature_map_path": "sigmap.json",
            "signature_map_path_full": "sigmap_full.json",
            "embedding_model_name": "dummy-model",
            "load_faiss_index": load_faiss,
            "load_signature_map": lambda *_a, **_k: None,
            "load_embedding_model": lambda *_a, **_k: None,
        }
        app = _ready_app()

        await readyz(_build_request(app))
        await health(_build_request(app))

        self.assertEqual(load_faiss.call_count, 1)


if __name__ == "__main__":
    unittest.main()
