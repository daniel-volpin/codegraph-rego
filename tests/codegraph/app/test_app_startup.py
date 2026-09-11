import unittest
from unittest.mock import Mock, patch

from fastapi import FastAPI

from codegraph.app import _preload_resources


class StartupPreloadTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.application = FastAPI()
        self.dependencies = {
            "embedding_model_name": "dummy-model",
            "check_java_parser": Mock(),
            "validate_generation": Mock(),
            "load_embedding_model": Mock(),
        }

    async def preload(self) -> dict:
        with patch("codegraph.app._load_startup_dependencies", return_value=self.dependencies):
            await _preload_resources(self.application)
        return self.application.state.startup_status

    async def test_preload_marks_app_ready_when_all_checks_pass(self) -> None:
        startup = await self.preload()
        self.assertTrue(startup["ready"])
        self.assertEqual(startup["phase"], "ready")
        self.assertEqual(startup["errors"], {})
        self.assertTrue(all(startup["checks"].values()))
        self.dependencies["validate_generation"].assert_called_once_with()

    async def test_incompatible_generation_prevents_readiness(self) -> None:
        self.dependencies["validate_generation"].side_effect = ValueError("rebuild required")
        startup = await self.preload()
        self.assertFalse(startup["ready"])
        self.assertFalse(startup["checks"]["graph_generation"])
        self.assertFalse(startup["checks"]["faiss_index"])
        self.assertIn("rebuild required", startup["errors"]["startup"])
        self.dependencies["validate_generation"].assert_called_once_with()
        self.dependencies["load_embedding_model"].assert_not_called()

    async def test_missing_java_parser_prevents_graph_access(self) -> None:
        self.dependencies["check_java_parser"].side_effect = RuntimeError("Java parser unavailable")
        startup = await self.preload()
        self.assertFalse(startup["ready"])
        self.assertFalse(startup["checks"]["java_parser"])
        self.dependencies["validate_generation"].assert_not_called()

    async def test_startup_never_ingests_or_mutates_the_graph(self) -> None:
        ingest = Mock(side_effect=AssertionError("Startup must be read-only"))
        with patch("codegraph.ingestion.service.ingest", ingest):
            await self.preload()
        ingest.assert_not_called()


if __name__ == "__main__":
    unittest.main()
