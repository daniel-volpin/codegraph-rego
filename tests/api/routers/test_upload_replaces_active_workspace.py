"""Uploading a codebase replaces the active workspace rather than adding one.

A workspace identity is derived from its source path, so ingesting from a new
location published a second ActiveWorkspace pointer and left the previous one
active. Evaluation reads every active workspace, so findings from a codebase the
user had replaced kept appearing. Remediation ingests a scratch worktree through
the same `ingest()`, which is why the deactivation belongs to this endpoint and
not to ingestion.
"""

from __future__ import annotations

import io
import os
import shutil
import unittest
import uuid
import zipfile
from pathlib import Path
from unittest.mock import ANY, patch

from fastapi import UploadFile

_WORK_ROOT = Path(__file__).resolve().parents[3] / "build" / "upload-replace-tests"


def _zip_bytes(path: str, content: str) -> bytes:
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w") as archive:
        archive.writestr(path, content)
    return payload.getvalue()


def _settings(upload_dir: str):
    from codegraph.config import get_settings

    return get_settings().model_copy(update={"upload_dir": upload_dir, "java_root_dir": upload_dir})


class TestUploadReplacesActiveWorkspace(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.enterContext(patch("api.routers.upload.rollback_workspace_revision"))
        _WORK_ROOT.mkdir(parents=True, exist_ok=True)
        self.case_dir = _WORK_ROOT / uuid.uuid4().hex
        self.case_dir.mkdir(parents=True, exist_ok=True)
        self.addCleanup(shutil.rmtree, self.case_dir, True)

    @patch("api.routers.upload.deactivate_other_workspaces", return_value=["stale-workspace"])
    @patch("api.routers.upload.EmbeddingService.build_embeddings")
    @patch("api.routers.upload.ingest")
    async def test_publishing_deactivates_every_other_workspace(
        self, mock_ingest, _mock_embeddings, mock_deactivate
    ) -> None:
        from api.routers.upload import upload_zip

        mock_ingest.return_value.workspace_id = "the-new-workspace"
        upload_dir = self.case_dir / "uploaded_code"
        upload_dir.mkdir()
        upload = UploadFile(
            filename="code.zip",
            file=io.BytesIO(_zip_bytes("src/main/java/com/example/App.java", "class App {}")),
        )

        with patch("api.routers.upload.settings", new=_settings(str(upload_dir))):
            response = await upload_zip(upload)

        self.assertEqual(response.status, "Codebase processed!")
        mock_deactivate.assert_called_once_with("the-new-workspace")

    @patch("api.routers.upload.deactivate_other_workspaces")
    @patch("api.routers.upload.EmbeddingService.build_embeddings")
    @patch("api.routers.upload.ingest")
    async def test_deactivation_runs_before_the_index_is_rebuilt(
        self, mock_ingest, mock_embeddings, mock_deactivate
    ) -> None:
        """Embeddings must describe the workspace that is actually active."""
        from api.routers.upload import upload_zip

        order: list[str] = []
        mock_ingest.return_value.workspace_id = "ws"
        mock_deactivate.side_effect = lambda *_a, **_k: order.append("deactivate") or []
        mock_embeddings.side_effect = lambda *_a, **_k: order.append("embeddings")

        upload_dir = self.case_dir / "uploaded_code"
        upload_dir.mkdir()
        upload = UploadFile(
            filename="code.zip",
            file=io.BytesIO(_zip_bytes("src/main/java/com/example/App.java", "class App {}")),
        )

        with patch("api.routers.upload.settings", new=_settings(str(upload_dir))):
            await upload_zip(upload)

        self.assertEqual(order, ["deactivate", "embeddings"])
        mock_ingest.assert_called_once_with(
            os.path.abspath(upload_dir), progress_callback=ANY, source_roots=ANY
        )
