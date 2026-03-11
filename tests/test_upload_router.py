import io
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from fastapi import UploadFile


def _build_zip_bytes(*entries: tuple[str, str]) -> bytes:
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w") as archive:
        for path, content in entries:
            archive.writestr(path, content)
    return payload.getvalue()


def _workspace_entries(root: Path) -> list[str]:
    return sorted(
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
    )


class TestUploadRouter(unittest.IsolatedAsyncioTestCase):
    @patch("api.routers.upload.EmbeddingService.build_embeddings")
    @patch("api.routers.upload.ingest")
    @patch("api.routers.upload.purge_workspace_entities")
    async def test_upload_replaces_workspace_only_after_validation(
        self,
        mock_purge_workspace_entities,
        mock_ingest,
        mock_build_embeddings,
    ) -> None:
        from api.routers.upload import upload_zip

        with tempfile.TemporaryDirectory() as tmp_dir:
            upload_dir = Path(tmp_dir) / "uploaded_code"
            upload_dir.mkdir()
            (upload_dir / "previous.txt").write_text("keep me until success", encoding="utf-8")

            upload = UploadFile(
                filename="code.zip",
                file=io.BytesIO(_build_zip_bytes(("src/main/java/com/example/App.java", "class App {}"))),
            )

            with patch("api.routers.upload.UPLOAD_DIR", str(upload_dir)):
                response = await upload_zip(upload)

            self.assertEqual(response.status, "Codebase processed!")
            self.assertFalse((upload_dir / "previous.txt").exists())
            self.assertTrue((upload_dir / "src" / "main" / "java" / "com" / "example" / "App.java").exists())
            mock_purge_workspace_entities.assert_called_once_with(os.path.abspath(upload_dir))
            mock_ingest.assert_called_once_with(
                os.path.abspath(upload_dir / "src" / "main" / "java"),
                progress_callback=unittest.mock.ANY,
                sync=True,
            )
            mock_build_embeddings.assert_called_once()

    @patch("api.routers.upload.EmbeddingService.build_embeddings")
    @patch("api.routers.upload.ingest")
    @patch("api.routers.upload.purge_workspace_entities")
    async def test_invalid_zip_preserves_previous_workspace(
        self,
        mock_purge_workspace_entities,
        mock_ingest,
        mock_build_embeddings,
    ) -> None:
        from api.routers.upload import upload_zip

        with tempfile.TemporaryDirectory() as tmp_dir:
            upload_dir = Path(tmp_dir) / "uploaded_code"
            upload_dir.mkdir()
            previous_file = upload_dir / "previous.txt"
            previous_file.write_text("existing workspace", encoding="utf-8")

            upload = UploadFile(filename="code.zip", file=io.BytesIO(b"not-a-zip"))

            with patch("api.routers.upload.UPLOAD_DIR", str(upload_dir)):
                response = await upload_zip(upload)

            self.assertEqual(response.status_code, 400)
            self.assertEqual(previous_file.read_text(encoding="utf-8"), "existing workspace")
            mock_purge_workspace_entities.assert_not_called()
            mock_ingest.assert_not_called()
            mock_build_embeddings.assert_not_called()

    @patch("api.routers.upload.EmbeddingService.build_embeddings")
    @patch("api.routers.upload.ingest")
    @patch("api.routers.upload.purge_workspace_entities")
    async def test_missing_java_root_preserves_previous_workspace(
        self,
        mock_purge_workspace_entities,
        mock_ingest,
        mock_build_embeddings,
    ) -> None:
        from api.routers.upload import upload_zip

        with tempfile.TemporaryDirectory() as tmp_dir:
            upload_dir = Path(tmp_dir) / "uploaded_code"
            upload_dir.mkdir()
            previous_file = upload_dir / "previous.txt"
            previous_file.write_text("existing workspace", encoding="utf-8")
            previous_snapshot = _workspace_entries(upload_dir)

            upload = UploadFile(
                filename="code.zip",
                file=io.BytesIO(_build_zip_bytes(("README.md", "no java here"))),
            )

            with patch("api.routers.upload.UPLOAD_DIR", str(upload_dir)):
                response = await upload_zip(upload)

            self.assertEqual(response.status_code, 400)
            self.assertEqual(_workspace_entries(upload_dir), previous_snapshot)
            self.assertEqual(previous_file.read_text(encoding="utf-8"), "existing workspace")
            mock_purge_workspace_entities.assert_not_called()
            mock_ingest.assert_not_called()
            mock_build_embeddings.assert_not_called()


if __name__ == "__main__":
    unittest.main()
