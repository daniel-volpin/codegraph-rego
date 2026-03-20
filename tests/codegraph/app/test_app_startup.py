import unittest
from unittest.mock import patch

from fastapi import FastAPI

from codegraph.app import _preload_resources


class StartupPreloadTests(unittest.IsolatedAsyncioTestCase):
    async def test_preload_marks_app_ready_when_all_checks_pass(self) -> None:
        application = FastAPI()

        with patch(
            "codegraph.app._load_startup_dependencies",
            return_value={
                "embedding_model_name": "dummy-model",
                "faiss_index_path": "index.faiss",
                "java_root_dir": "uploaded_code",
                "signature_map_path": "sigmap.json",
                "signature_map_path_full": "sigmap_full.json",
                "ingest": lambda *_args, **_kwargs: None,
                "load_embedding_model": lambda *_args, **_kwargs: None,
                "load_faiss_index": lambda *_args, **_kwargs: None,
                "load_signature_map": lambda *_args, **_kwargs: None,
            },
        ):
            await _preload_resources(application)

        startup = application.state.startup_status
        self.assertTrue(startup["ready"])
        self.assertEqual(startup["phase"], "ready")
        self.assertEqual(startup["errors"], {})
        self.assertTrue(all(startup["checks"].values()))

    async def test_preload_marks_app_degraded_when_ingestion_fails(self) -> None:
        application = FastAPI()

        def _fail_ingest(*_args, **_kwargs) -> None:
            raise RuntimeError("ingest failed")

        with patch(
            "codegraph.app._load_startup_dependencies",
            return_value={
                "embedding_model_name": "dummy-model",
                "faiss_index_path": "index.faiss",
                "java_root_dir": "uploaded_code",
                "signature_map_path": "sigmap.json",
                "signature_map_path_full": "sigmap_full.json",
                "ingest": _fail_ingest,
                "load_embedding_model": lambda *_args, **_kwargs: None,
                "load_faiss_index": lambda *_args, **_kwargs: None,
                "load_signature_map": lambda *_args, **_kwargs: None,
            },
        ):
            await _preload_resources(application)

        startup = application.state.startup_status
        self.assertFalse(startup["ready"])
        self.assertEqual(startup["phase"], "degraded")
        self.assertIn("ingestion", startup["errors"])
        self.assertEqual(startup["errors"]["ingestion"], "ingest failed")
        self.assertFalse(startup["checks"]["ingestion"])


if __name__ == "__main__":
    unittest.main()
