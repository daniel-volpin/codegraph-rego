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
            "java_parser": True,
            "graph_generation": True,
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
            "java_parser": True,
            "graph_generation": False,
            "signature_map": False,
            "faiss_index": False,
            "embedding_model": False,
        },
        "errors": {"startup": "graph/index revision mismatch"},
    }
    return app


def _ready_search_deps() -> dict:
    return {
        "embedding_model_name": "dummy-model",
        "validate_generation": lambda: None,
        "load_embedding_model": lambda *_args, **_kwargs: None,
    }


class HealthRouterTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        # Reset the readiness cache between tests so outcomes don't leak.
        from api.routers.health import reset_readiness_cache

        reset_readiness_cache()

    @patch("api.routers.health._opa_probe", return_value=(True, None))
    @patch("api.routers.health._load_search_health_dependencies")
    @patch("api.routers.health.shared_neo4j_driver", return_value=_FakeDriver())
    async def test_health_returns_ok_when_runtime_is_ready(
        self,
        _mock_driver,
        mock_search_deps,
        _mock_opa,
    ) -> None:
        from api.routers.health import health

        mock_search_deps.return_value = _ready_search_deps()

        response = await health(_build_request(_ready_app()))

        self.assertEqual(response.status_code, 200)
        payload = json.loads(response.body)
        self.assertEqual(payload["status"], "ok")
        self.assertTrue(payload["startup_ready"])
        self.assertEqual(payload["startup"]["phase"], "ready")

    @patch("api.routers.health._opa_probe", return_value=(True, None))
    @patch("api.routers.health._load_search_health_dependencies")
    @patch("api.routers.health.shared_neo4j_driver", return_value=_FakeDriver())
    async def test_health_returns_degraded_when_startup_is_degraded(
        self,
        _mock_driver,
        mock_search_deps,
        _mock_opa,
    ) -> None:
        from api.routers.health import health

        mock_search_deps.return_value = _ready_search_deps()

        response = await health(_build_request(_degraded_app()))

        self.assertEqual(response.status_code, 503)
        payload = json.loads(response.body)
        self.assertEqual(payload["status"], "degraded")
        self.assertFalse(payload["startup_ready"])
        self.assertEqual(payload["startup"]["errors"]["startup"], "graph/index revision mismatch")
        self.assertEqual(payload["details"]["startup"]["startup"], "graph/index revision mismatch")


class HealthzLivenessTests(unittest.IsolatedAsyncioTestCase):
    """GET /healthz is a cheap liveness probe with no external I/O."""

    async def test_healthz_returns_200_alive(self) -> None:
        from api.routers.health import healthz

        result = await healthz()

        self.assertEqual(result.status, "alive")

    @patch("api.routers.health.shared_neo4j_driver")
    @patch("api.routers.health._load_search_health_dependencies")
    @patch("api.routers.health._opa_probe")
    async def test_healthz_does_no_external_io(
        self,
        mock_opa,
        mock_search_deps,
        mock_driver,
    ) -> None:
        from api.routers.health import healthz

        await healthz()

        mock_driver.assert_not_called()
        mock_search_deps.assert_not_called()
        mock_opa.assert_not_called()


class ReadyzCachingTests(unittest.IsolatedAsyncioTestCase):
    """GET /readyz exercises every dependency, but caches for 30 seconds."""

    def setUp(self) -> None:
        from api.routers.health import reset_readiness_cache

        reset_readiness_cache()

    @patch("api.routers.health._opa_probe", return_value=(True, None))
    @patch("api.routers.health._load_search_health_dependencies")
    @patch("api.routers.health.shared_neo4j_driver")
    async def test_readyz_reports_dependency_status(
        self,
        mock_driver,
        mock_search_deps,
        _mock_opa,
    ) -> None:
        from api.routers.health import readyz

        mock_driver.return_value = _FakeDriver()
        mock_search_deps.return_value = _ready_search_deps()

        response = await readyz(_build_request(_ready_app()))

        self.assertEqual(response.status_code, 200)
        payload = json.loads(response.body)
        self.assertEqual(payload["status"], "ok")

    @patch("api.routers.health._opa_probe", return_value=(True, None))
    @patch("api.routers.health._load_search_health_dependencies")
    @patch("api.routers.health.shared_neo4j_driver")
    async def test_readyz_caches_second_call_within_ttl(
        self,
        mock_driver,
        mock_search_deps,
        _mock_opa,
    ) -> None:
        """Second /readyz within the TTL must not re-probe Neo4j or FAISS."""
        from api.routers.health import readyz

        mock_driver.return_value = _FakeDriver()
        validate_generation = MagicMock(return_value=None)
        load_embed = MagicMock(return_value=None)
        mock_search_deps.return_value = {
            "embedding_model_name": "dummy-model",
            "validate_generation": validate_generation,
            "load_embedding_model": load_embed,
        }
        app = _ready_app()

        await readyz(_build_request(app))
        await readyz(_build_request(app))
        await readyz(_build_request(app))

        # First call performs one probe each; second and third hit the cache.
        self.assertEqual(validate_generation.call_count, 1)
        self.assertEqual(load_embed.call_count, 1)
        # Neo4j driver fetched exactly once for the same reason.
        self.assertEqual(mock_driver.call_count, 1)

    @patch("api.routers.health._opa_probe", return_value=(True, None))
    @patch("api.routers.health._load_search_health_dependencies")
    @patch("api.routers.health.shared_neo4j_driver", return_value=_FakeDriver())
    async def test_health_and_readyz_share_the_cache(
        self,
        _mock_driver,
        mock_search_deps,
        _mock_opa,
    ) -> None:
        """The legacy /health alias and /readyz must hit one shared cache."""
        from api.routers.health import health, readyz

        validate_generation = MagicMock(return_value=None)
        mock_search_deps.return_value = {
            "embedding_model_name": "dummy-model",
            "validate_generation": validate_generation,
            "load_embedding_model": lambda *_a, **_k: None,
        }
        app = _ready_app()

        await readyz(_build_request(app))
        await health(_build_request(app))

        self.assertEqual(validate_generation.call_count, 1)

    @patch("api.routers.health._opa_probe", return_value=(True, None))
    @patch("api.routers.health._load_search_health_dependencies")
    @patch("api.routers.health.shared_neo4j_driver", return_value=_FakeDriver())
    async def test_reachable_graph_with_stale_index_is_not_ready(
        self, _mock_driver, mock_search_deps, _mock_opa,
    ) -> None:
        from api.routers.health import readyz

        deps = _ready_search_deps()
        deps["validate_generation"] = MagicMock(side_effect=ValueError("graph/index revision mismatch"))
        mock_search_deps.return_value = deps
        response = await readyz(_build_request(_ready_app()))
        payload = json.loads(response.body)
        self.assertEqual(response.status_code, 503)
        self.assertTrue(payload["neo4j"])
        self.assertFalse(payload["graph_generation"])
        self.assertFalse(payload["faiss_index"])
        self.assertEqual(payload["details"]["search"], "graph/index revision mismatch")

    @patch("api.routers.health._opa_probe", return_value=(False, "opa version probe failed: bad binary"))
    @patch("api.routers.health._load_search_health_dependencies")
    @patch("api.routers.health.shared_neo4j_driver", return_value=_FakeDriver())
    async def test_readyz_reports_opa_probe_failure(
        self,
        _mock_driver,
        mock_search_deps,
        _mock_opa,
    ) -> None:
        from api.routers.health import readyz

        mock_search_deps.return_value = _ready_search_deps()

        response = await readyz(_build_request(_ready_app()))

        self.assertEqual(response.status_code, 503)
        payload = json.loads(response.body)
        self.assertFalse(payload["opa"])
        self.assertEqual(payload["details"]["opa"], "opa version probe failed: bad binary")


class OpaProbeTests(unittest.TestCase):
    @patch("api.routers.health.shutil.which", return_value="/usr/local/bin/opa")
    @patch("api.routers.health.subprocess.run")
    def test_opa_probe_accepts_json_version_output(self, mock_run, _mock_which) -> None:
        from api.routers.health import _opa_probe

        mock_run.return_value = MagicMock(returncode=0, stdout='{"version":"1.15.1"}', stderr="")

        result = _opa_probe()

        self.assertEqual(result, (True, None))
        mock_run.assert_called_once_with(
            ["/usr/local/bin/opa", "version", "--format=json"],
            capture_output=True,
            text=True,
        )

    @patch("api.routers.health.shutil.which", return_value="/usr/local/bin/opa")
    @patch("api.routers.health.subprocess.run")
    def test_opa_probe_falls_back_to_plain_text_version_output(self, mock_run, _mock_which) -> None:
        from api.routers.health import _opa_probe

        mock_run.side_effect = [
            MagicMock(returncode=1, stdout="", stderr="unknown flag: --format"),
            MagicMock(returncode=0, stdout="Version: 1.15.1\nGo Version: go1.26.1\n", stderr=""),
        ]

        result = _opa_probe()

        self.assertEqual(result, (True, None))
        self.assertEqual(mock_run.call_count, 2)

    @patch("api.routers.health.shutil.which", return_value="/usr/local/bin/opa")
    @patch("api.routers.health.subprocess.run")
    def test_opa_probe_reports_failure_when_plain_text_fallback_has_no_version(self, mock_run, _mock_which) -> None:
        from api.routers.health import _opa_probe

        mock_run.side_effect = [
            MagicMock(returncode=1, stdout="", stderr="unknown flag: --format"),
            MagicMock(returncode=0, stdout="Go Version: go1.26.1\n", stderr=""),
        ]

        result = _opa_probe()

        self.assertEqual(result, (False, "opa version probe returned missing version metadata"))


if __name__ == "__main__":
    unittest.main()
