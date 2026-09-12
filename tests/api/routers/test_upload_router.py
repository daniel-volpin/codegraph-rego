import asyncio
import io
import os
import shutil
import threading
import time
import types
import unittest
import uuid
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from fastapi import UploadFile

from codegraph.ingestion.service import IngestionError, WorkspacePublication

_TEST_WORK_ROOT = Path(__file__).resolve().parents[3] / ".copilot-upload-router-test-work"


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
    return sorted(path.relative_to(root).as_posix() for path in root.rglob("*"))


@contextmanager
def _workspace_case() -> Iterator[Path]:
    _TEST_WORK_ROOT.mkdir(parents=True, exist_ok=True)
    case_dir = _TEST_WORK_ROOT / uuid.uuid4().hex
    case_dir.mkdir(parents=True, exist_ok=True)
    try:
        yield case_dir
    finally:
        shutil.rmtree(case_dir, ignore_errors=True)
        try:
            _TEST_WORK_ROOT.rmdir()
        except OSError:
            pass


class TestUploadRouter(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.rollback = self.enterContext(patch("api.routers.upload.rollback_workspace_revision"))

    @patch("api.routers.upload.EmbeddingService.build_embeddings")
    @patch("api.routers.upload.ingest")
    async def test_upload_replaces_workspace_only_after_validation(
        self,
        mock_ingest,
        mock_build_embeddings,
    ) -> None:
        from api.routers.upload import upload_zip

        with _workspace_case() as case_dir:
            upload_dir = case_dir / "uploaded_code"
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
            mock_ingest.assert_called_once_with(
                os.path.abspath(upload_dir),
                progress_callback=unittest.mock.ANY,
                source_roots=[os.path.abspath(upload_dir / "src" / "main" / "java")],
            )
            mock_build_embeddings.assert_called_once()

    @patch("api.routers.upload.EmbeddingService.build_embeddings")
    @patch("api.routers.upload.ingest")
    async def test_upload_uses_client_request_id(
        self,
        mock_ingest,
        _mock_build_embeddings,
    ) -> None:
        from api.routers.upload import upload_zip

        with _workspace_case() as case_dir:
            upload_dir = case_dir / "uploaded_code"
            upload = UploadFile(
                filename="code.zip",
                file=io.BytesIO(_build_zip_bytes(("src/main/java/App.java", "class App {}"))),
            )
            with patch("api.routers.upload.settings", new=_test_settings(str(upload_dir))):
                response = await upload_zip(upload, request_id_header="client-job-123")

            self.assertEqual(response.request_id, "client-job-123")

    @patch("api.routers.upload.EmbeddingService.build_embeddings")
    @patch("api.routers.upload.ingest")
    async def test_concurrent_upload_publications_are_serialized(
        self,
        mock_ingest,
        _mock_build_embeddings,
    ) -> None:
        from api.routers.upload import upload_zip

        active = 0
        max_active = 0
        counter_lock = threading.Lock()

        def slow_ingest(*_args, **_kwargs):
            nonlocal active, max_active
            with counter_lock:
                active += 1
                max_active = max(max_active, active)
            time.sleep(0.05)
            with counter_lock:
                active -= 1
            return WorkspacePublication("workspace", uuid.uuid4().hex, None)

        mock_ingest.side_effect = slow_ingest
        with _workspace_case() as case_dir:
            upload_dir = case_dir / "uploaded_code"
            first = UploadFile(
                filename="first.zip",
                file=io.BytesIO(_build_zip_bytes(("one/src/main/java/One.java", "class One {}"))),
            )
            second = UploadFile(
                filename="second.zip",
                file=io.BytesIO(_build_zip_bytes(("two/src/main/java/Two.java", "class Two {}"))),
            )
            with patch("api.routers.upload.settings", new=_test_settings(str(upload_dir))):
                responses = await asyncio.gather(
                    upload_zip(first, request_id_header="first"),
                    upload_zip(second, request_id_header="second"),
                )

        self.assertEqual(max_active, 1)
        self.assertTrue(all(response.status == "Codebase processed!" for response in responses))

    @patch("api.routers.upload.EmbeddingService.build_embeddings")
    @patch("api.routers.upload.ingest")
    async def test_upload_ingests_one_workspace_with_all_java_roots_in_sorted_order(
        self,
        mock_ingest,
        mock_build_embeddings,
    ) -> None:
        from api.routers.upload import upload_zip

        with _workspace_case() as case_dir:
            upload_dir = case_dir / "uploaded_code"
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
            mock_ingest.assert_called_once_with(
                os.path.abspath(upload_dir),
                progress_callback=unittest.mock.ANY,
                source_roots=expected_roots,
            )
            mock_build_embeddings.assert_called_once()

    @patch("api.routers.upload.EmbeddingService.build_embeddings")
    @patch("api.routers.upload.ingest")
    async def test_invalid_zip_preserves_previous_workspace(
        self,
        mock_ingest,
        mock_build_embeddings,
    ) -> None:
        from api.routers.upload import upload_zip

        with _workspace_case() as case_dir:
            upload_dir = case_dir / "uploaded_code"
            upload_dir.mkdir()
            previous_file = upload_dir / "previous.txt"
            previous_file.write_text("existing workspace", encoding="utf-8")

            upload = UploadFile(filename="code.zip", file=io.BytesIO(b"not-a-zip"))

            with patch("api.routers.upload.settings", new=_test_settings(str(upload_dir))):
                response = await upload_zip(upload)

            self.assertEqual(response.status_code, 400)
            self.assertEqual(previous_file.read_text(encoding="utf-8"), "existing workspace")
            mock_ingest.assert_not_called()
            mock_build_embeddings.assert_not_called()

    @patch("api.routers.upload.safe_extract_zip")
    @patch("api.routers.upload.EmbeddingService.build_embeddings")
    @patch("api.routers.upload.ingest")
    async def test_oversized_upload_is_rejected_before_extraction(
        self,
        mock_ingest,
        mock_build_embeddings,
        mock_safe_extract_zip,
    ) -> None:
        from api.routers.upload import upload_zip

        with _workspace_case() as case_dir:
            upload_dir = case_dir / "uploaded_code"
            upload_dir.mkdir()
            previous_file = upload_dir / "previous.txt"
            previous_file.write_text("existing workspace", encoding="utf-8")

            upload = UploadFile(filename="code.zip", file=io.BytesIO(b"0123456789ABCDEF"))

            with patch(
                "api.routers.upload.settings", new=_test_settings(str(upload_dir), upload_max_archive_size_bytes=8)
            ):
                response = await upload_zip(upload)

            self.assertEqual(response.status_code, 400)
            self.assertIn("size limit", response.body.decode("utf-8"))
            self.assertEqual(previous_file.read_text(encoding="utf-8"), "existing workspace")
            mock_safe_extract_zip.assert_not_called()
            mock_ingest.assert_not_called()
            mock_build_embeddings.assert_not_called()

    @patch("api.routers.upload.EmbeddingService.build_embeddings")
    @patch("api.routers.upload.ingest")
    async def test_missing_java_root_preserves_previous_workspace(
        self,
        mock_ingest,
        mock_build_embeddings,
    ) -> None:
        from api.routers.upload import upload_zip

        with _workspace_case() as case_dir:
            upload_dir = case_dir / "uploaded_code"
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
            mock_ingest.assert_not_called()
            mock_build_embeddings.assert_not_called()

    @patch("api.routers.upload.EmbeddingService.build_embeddings")
    @patch("api.routers.upload.ingest")
    async def test_failed_ingestion_restores_previous_workspace_without_rebuilding_embeddings(
        self,
        mock_ingest,
        mock_build_embeddings,
    ) -> None:
        from api.routers.upload import upload_zip

        with _workspace_case() as case_dir:
            upload_dir = case_dir / "uploaded_code"
            old_root_a = upload_dir / "module-a" / "src" / "main" / "java" / "com" / "example"
            old_root_b = upload_dir / "module-b" / "src" / "main" / "java" / "com" / "example"
            old_root_a.mkdir(parents=True)
            old_root_b.mkdir(parents=True)
            (old_root_a / "OldA.java").write_text("class OldA {}", encoding="utf-8")
            (old_root_b / "OldB.java").write_text("class OldB {}", encoding="utf-8")

            upload = UploadFile(
                filename="code.zip",
                file=io.BytesIO(
                    _build_zip_bytes(("new-module/src/main/java/com/example/NewApp.java", "class NewApp {}"))
                ),
            )

            mock_ingest.side_effect = RuntimeError("boom")

            with patch("api.routers.upload.settings", new=_test_settings(str(upload_dir))):
                response = await upload_zip(upload)

            self.assertEqual(response.status_code, 500)
            self.assertTrue((old_root_a / "OldA.java").exists())
            self.assertTrue((old_root_b / "OldB.java").exists())
            self.assertFalse((upload_dir / "new-module").exists())
            mock_ingest.assert_called_once_with(
                os.path.abspath(upload_dir),
                progress_callback=unittest.mock.ANY,
                source_roots=[os.path.abspath(upload_dir / "new-module" / "src" / "main" / "java")],
            )
            mock_build_embeddings.assert_not_called()

    @patch("api.routers.upload.EmbeddingService.build_embeddings")
    @patch("api.routers.upload.ingest")
    async def test_failed_embedding_build_restores_previous_workspace_and_graph(
        self,
        mock_ingest,
        mock_build_embeddings,
    ) -> None:
        from api.routers.upload import upload_zip

        with _workspace_case() as case_dir:
            upload_dir = case_dir / "uploaded_code"
            old_root_a = upload_dir / "module-a" / "src" / "main" / "java" / "com" / "example"
            old_root_b = upload_dir / "module-b" / "src" / "main" / "java" / "com" / "example"
            old_root_a.mkdir(parents=True)
            old_root_b.mkdir(parents=True)
            (old_root_a / "OldA.java").write_text("class OldA {}", encoding="utf-8")
            (old_root_b / "OldB.java").write_text("class OldB {}", encoding="utf-8")

            upload = UploadFile(
                filename="code.zip",
                file=io.BytesIO(
                    _build_zip_bytes(("new-module/src/main/java/com/example/NewApp.java", "class NewApp {}"))
                ),
            )

            mock_build_embeddings.side_effect = RuntimeError("embedding boom")

            with patch("api.routers.upload.settings", new=_test_settings(str(upload_dir))):
                response = await upload_zip(upload)

            self.assertEqual(response.status_code, 500)
            self.assertTrue((old_root_a / "OldA.java").exists())
            self.assertTrue((old_root_b / "OldB.java").exists())
            self.assertFalse((upload_dir / "new-module").exists())
            self.assertEqual(
                [call.args[0] for call in mock_ingest.call_args_list],
                [os.path.abspath(upload_dir)],
            )
            self.assertEqual(
                [call.kwargs["source_roots"] for call in mock_ingest.call_args_list],
                [
                    [os.path.abspath(upload_dir / "new-module" / "src" / "main" / "java")],
                ],
            )
            mock_build_embeddings.assert_called_once()
            self.rollback.assert_called_once_with(mock_ingest.return_value)

    @patch("api.routers.upload.EmbeddingService.build_embeddings")
    @patch("api.routers.upload.ingest")
    async def test_failed_embedding_restore_reports_restore_error(
        self,
        mock_ingest,
        mock_build_embeddings,
    ) -> None:
        from api.routers.upload import upload_zip

        with _workspace_case() as case_dir:
            upload_dir = case_dir / "uploaded_code"
            old_root = upload_dir / "module-a" / "src" / "main" / "java" / "com" / "example"
            old_root.mkdir(parents=True)
            (old_root / "OldA.java").write_text("class OldA {}", encoding="utf-8")

            upload = UploadFile(
                filename="code.zip",
                file=io.BytesIO(
                    _build_zip_bytes(("new-module/src/main/java/com/example/NewApp.java", "class NewApp {}"))
                ),
            )

            mock_build_embeddings.side_effect = RuntimeError("embedding boom")
            self.rollback.side_effect = IngestionError("restore workspace failed")

            with patch("api.routers.upload.settings", new=_test_settings(str(upload_dir))):
                response = await upload_zip(upload)

            self.assertEqual(response.status_code, 500)
            self.assertIn("Restore also failed", response.body.decode("utf-8"))
            self.assertTrue((old_root / "OldA.java").exists())

    @patch("api.routers.upload.EmbeddingService.build_embeddings", side_effect=RuntimeError("embedding failed"))
    @patch("api.routers.upload.ingest")
    async def test_first_upload_failure_rolls_back_publication_without_a_previous_workspace(self, ingest, _embeddings):
        from api.routers.upload import upload_zip

        receipt = WorkspacePublication("workspace", "new-revision", None)
        ingest.return_value = receipt
        with _workspace_case() as case_dir:
            upload_dir = case_dir / "uploaded_code"
            upload = UploadFile(
                filename="code.zip",
                file=io.BytesIO(_build_zip_bytes(("src/main/java/App.java", "class App {}"))),
            )
            with patch("api.routers.upload.settings", new=_test_settings(str(upload_dir))):
                response = await upload_zip(upload)
            self.assertEqual(response.status_code, 500)
            self.assertFalse(upload_dir.exists())
            self.rollback.assert_called_once_with(receipt)


if __name__ == "__main__":
    unittest.main()
