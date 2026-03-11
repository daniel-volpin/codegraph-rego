import io
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from fastapi import UploadFile


def _build_zip_bytes() -> bytes:
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w") as archive:
        archive.writestr("src/main/java/com/example/App.java", "class App {}")
    return payload.getvalue()


class TestUploadRouter(unittest.IsolatedAsyncioTestCase):
    @patch("api.routers.upload.EmbeddingService.build_embeddings")
    @patch("api.routers.upload.ingest")
    @patch("api.routers.upload.purge_workspace_entities")
    @patch("api.routers.upload.find_java_root")
    @patch("api.routers.upload.safe_extract_zip")
    async def test_upload_resets_workspace_graph_before_ingest(
        self,
        _mock_extract,
        mock_find_java_root,
        mock_purge_workspace_entities,
        mock_ingest,
        _mock_build_embeddings,
    ) -> None:
        from api.routers.upload import upload_zip

        with tempfile.TemporaryDirectory() as tmp_dir:
            java_root = str(Path(tmp_dir) / "src" / "main" / "java")
            mock_find_java_root.return_value = java_root

            upload = UploadFile(
                filename="code.zip",
                file=io.BytesIO(_build_zip_bytes()),
            )

            with patch("api.routers.upload.UPLOAD_DIR", tmp_dir):
                response = await upload_zip(upload)

        self.assertEqual(response.status, "Codebase processed!")
        self.assertEqual(response.java_root, java_root)
        mock_purge_workspace_entities.assert_called_once_with(os.path.abspath(tmp_dir))
        mock_ingest.assert_called_once()
        self.assertEqual(mock_ingest.call_args.args[0], java_root)


if __name__ == "__main__":
    unittest.main()
