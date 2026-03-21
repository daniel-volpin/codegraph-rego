import io
import os
import tempfile
import types
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from fastapi import UploadFile

from codegraph.ingestion.service import IngestionError


def _test_settings(upload_dir: str, **overrides) -> types.SimpleNamespace:
    """Minimal settings namespace for upload router tests."""
    defaults = dict(
        upload_dir=upload_dir,
        upload_max_archive_size_bytes=100 * 1024 * 1024,
        upload_max_member_size_bytes=50 * 1024 * 1024,
        upload_max_extracted_size_bytes=500 * 1024 * 1024,
        upload_max_archive_entries=10_000,
        upload_max_compression_ratio=100.0,
    )
    defaults.update(overrides)
    return types.SimpleNamespace(**defaults)


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

            with patch("api.routers.upload.settings", new=_test_settings(str(upload_dir))):
                response = await upload_zip(upload)

            self.assertEqual(response.status, "Codebase processed!")
            self.assertEqual(
                response.java_roots,
                [os.path.abspath(upload_dir / "src" / "main" / "java")],
            )
            self.assertFalse((upload_dir / "previous.txt").exists())
            self.assertTrue((upload_dir / "src" / "main" / "java" / "com" / "example" / "App.java").exists())
            mock_purge_workspace_entities.assert_called_once_with(os.path.abspath(upload_dir))
            mock_ingest.assert_called_once_with(
                os.path.abspath(upload_dir / "src" / "main" / "java"),
                progress_callback=unittest.mock.ANY,
                sync=False,
            )
            mock_build_embeddings.assert_called_once()

    @patch("api.routers.upload.EmbeddingService.build_embeddings")
    @patch("api.routers.upload.ingest")
    @patch("api.routers.upload.purge_workspace_entities")
    async def test_upload_ingests_all_java_roots_in_sorted_order(
        self,
        mock_purge_workspace_entities,
        mock_ingest,
        mock_build_embeddings,
    ) -> None:
        from api.routers.upload import upload_zip

        with tempfile.TemporaryDirectory() as tmp_dir:
            upload_dir = Path(tmp_dir) / "uploaded_code"
            upload_dir.mkdir()

            upload = UploadFile(
                filename="code.zip",
                file=io.BytesIO(
                    _build_zip_bytes(
                        ("z-module/src/main/java/com/example/ZApp.java", "class ZApp {}"),
                        ("a-module/src/main/java/com/example/AApp.java", "class AApp {}"),
                    )
                ),
            )

            with patch("api.routers.upload.settings", new=_test_settings(str(upload_dir))):
                response = await upload_zip(upload)

            expected_roots = [
                os.path.abspath(upload_dir / "a-module" / "src" / "main" / "java"),
                os.path.abspath(upload_dir / "z-module" / "src" / "main" / "java"),
            ]
            self.assertEqual(response.status, "Codebase processed!")
            self.assertEqual(response.java_root, expected_roots[0])
            self.assertEqual(response.java_roots, expected_roots)
            self.assertEqual(
                [call.kwargs for call in mock_ingest.call_args_list],
                [
                    {"progress_callback": unittest.mock.ANY, "sync": False},
                    {"progress_callback": unittest.mock.ANY, "sync": False},
                ],
            )
            self.assertEqual(
                [call.args[0] for call in mock_ingest.call_args_list],
                expected_roots,
            )
            mock_purge_workspace_entities.assert_called_once_with(os.path.abspath(upload_dir))
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

            with patch("api.routers.upload.settings", new=_test_settings(str(upload_dir))):
                response = await upload_zip(upload)

            self.assertEqual(response.status_code, 400)
            self.assertEqual(previous_file.read_text(encoding="utf-8"), "existing workspace")
            mock_purge_workspace_entities.assert_not_called()
            mock_ingest.assert_not_called()
            mock_build_embeddings.assert_not_called()

    @patch("api.routers.upload.safe_extract_zip")
    @patch("api.routers.upload.EmbeddingService.build_embeddings")
    @patch("api.routers.upload.ingest")
    @patch("api.routers.upload.purge_workspace_entities")
    async def test_oversized_upload_is_rejected_before_extraction(
        self,
        mock_purge_workspace_entities,
        mock_ingest,
        mock_build_embeddings,
        mock_safe_extract_zip,
    ) -> None:
        from api.routers.upload import upload_zip

        with tempfile.TemporaryDirectory() as tmp_dir:
            upload_dir = Path(tmp_dir) / "uploaded_code"
            upload_dir.mkdir()
            previous_file = upload_dir / "previous.txt"
            previous_file.write_text("existing workspace", encoding="utf-8")

            upload = UploadFile(filename="code.zip", file=io.BytesIO(b"0123456789ABCDEF"))

            with patch("api.routers.upload.settings", new=_test_settings(str(upload_dir), upload_max_archive_size_bytes=8)):
                response = await upload_zip(upload)

            self.assertEqual(response.status_code, 400)
            self.assertIn("size limit", response.body.decode("utf-8"))
            self.assertEqual(previous_file.read_text(encoding="utf-8"), "existing workspace")
            mock_safe_extract_zip.assert_not_called()
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

            with patch("api.routers.upload.settings", new=_test_settings(str(upload_dir))):
                response = await upload_zip(upload)

            self.assertEqual(response.status_code, 400)
            self.assertEqual(_workspace_entries(upload_dir), previous_snapshot)
            self.assertEqual(previous_file.read_text(encoding="utf-8"), "existing workspace")
            mock_purge_workspace_entities.assert_not_called()
            mock_ingest.assert_not_called()
            mock_build_embeddings.assert_not_called()

    @patch("api.routers.upload.EmbeddingService.build_embeddings")
    @patch("api.routers.upload.ingest")
    @patch("api.routers.upload.purge_workspace_entities")
    async def test_failed_ingestion_restores_previous_multi_root_workspace(
        self,
        mock_purge_workspace_entities,
        mock_ingest,
        mock_build_embeddings,
    ) -> None:
        from api.routers.upload import upload_zip

        with tempfile.TemporaryDirectory() as tmp_dir:
            upload_dir = Path(tmp_dir) / "uploaded_code"
            old_root_a = upload_dir / "module-a" / "src" / "main" / "java" / "com" / "example"
            old_root_b = upload_dir / "module-b" / "src" / "main" / "java" / "com" / "example"
            old_root_a.mkdir(parents=True)
            old_root_b.mkdir(parents=True)
            (old_root_a / "OldA.java").write_text("class OldA {}", encoding="utf-8")
            (old_root_b / "OldB.java").write_text("class OldB {}", encoding="utf-8")

            upload = UploadFile(
                filename="code.zip",
                file=io.BytesIO(_build_zip_bytes(("new-module/src/main/java/com/example/NewApp.java", "class NewApp {}"))),
            )

            mock_ingest.side_effect = [RuntimeError("boom"), None, None]

            with patch("api.routers.upload.settings", new=_test_settings(str(upload_dir))):
                response = await upload_zip(upload)

            self.assertEqual(response.status_code, 500)
            self.assertTrue((old_root_a / "OldA.java").exists())
            self.assertTrue((old_root_b / "OldB.java").exists())
            self.assertFalse((upload_dir / "new-module").exists())
            self.assertEqual(mock_purge_workspace_entities.call_count, 2)
            self.assertEqual(
                [call.args[0] for call in mock_ingest.call_args_list],
                [
                    os.path.abspath(upload_dir / "new-module" / "src" / "main" / "java"),
                    os.path.abspath(upload_dir / "module-a" / "src" / "main" / "java"),
                    os.path.abspath(upload_dir / "module-b" / "src" / "main" / "java"),
                ],
            )
            self.assertTrue(all(call.kwargs["sync"] is False for call in mock_ingest.call_args_list))
            mock_build_embeddings.assert_called_once()

    @patch("api.routers.upload.EmbeddingService.build_embeddings")
    @patch("api.routers.upload.ingest")
    @patch("api.routers.upload.purge_workspace_entities")
    async def test_failed_restore_ingestion_does_not_build_embeddings(
        self,
        mock_purge_workspace_entities,
        mock_ingest,
        mock_build_embeddings,
    ) -> None:
        from api.routers.upload import upload_zip

        with tempfile.TemporaryDirectory() as tmp_dir:
            upload_dir = Path(tmp_dir) / "uploaded_code"
            old_root_a = upload_dir / "module-a" / "src" / "main" / "java" / "com" / "example"
            old_root_b = upload_dir / "module-b" / "src" / "main" / "java" / "com" / "example"
            old_root_a.mkdir(parents=True)
            old_root_b.mkdir(parents=True)
            (old_root_a / "OldA.java").write_text("class OldA {}", encoding="utf-8")
            (old_root_b / "OldB.java").write_text("class OldB {}", encoding="utf-8")

            upload = UploadFile(
                filename="code.zip",
                file=io.BytesIO(_build_zip_bytes(("new-module/src/main/java/com/example/NewApp.java", "class NewApp {}"))),
            )

            mock_ingest.side_effect = [
                IngestionError("new workspace failed"),
                IngestionError("restore workspace failed"),
            ]

            with patch("api.routers.upload.settings", new=_test_settings(str(upload_dir))):
                response = await upload_zip(upload)

            self.assertEqual(response.status_code, 500)
            self.assertIn("Restore also failed", response.body.decode("utf-8"))
            self.assertTrue((old_root_a / "OldA.java").exists())
            self.assertTrue((old_root_b / "OldB.java").exists())
            self.assertFalse((upload_dir / "new-module").exists())
            self.assertEqual(mock_purge_workspace_entities.call_count, 2)
            mock_build_embeddings.assert_not_called()


if __name__ == "__main__":
    unittest.main()
