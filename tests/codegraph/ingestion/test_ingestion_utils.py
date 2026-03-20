import io
import os
import tempfile
import unittest
import zipfile
from pathlib import Path

from codegraph.ingestion.utils import UploadValidationError, find_java_roots, safe_extract_zip


def _build_zip(entries: list[tuple[str, bytes]], compression: int = zipfile.ZIP_STORED) -> bytes:
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w", compression=compression) as archive:
        for path, content in entries:
            archive.writestr(path, content)
    return payload.getvalue()


class IngestionUtilsTests(unittest.TestCase):
    def test_find_java_roots_returns_sorted_roots(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            workspace = Path(tmp_dir)
            (workspace / "z-module" / "src" / "main" / "java").mkdir(parents=True)
            (workspace / "a-module" / "src" / "main" / "java").mkdir(parents=True)

            roots = find_java_roots(tmp_dir)

            self.assertEqual(
                roots,
                [
                    os.path.abspath(workspace / "a-module" / "src" / "main" / "java"),
                    os.path.abspath(workspace / "z-module" / "src" / "main" / "java"),
                ],
            )

    def test_safe_extract_zip_rejects_total_size_limit(self) -> None:
        archive_bytes = _build_zip(
            [
                ("src/main/java/A.java", b"class A {}"),
                ("src/main/java/B.java", b"class B {}"),
            ]
        )

        with tempfile.TemporaryDirectory() as tmp_dir, zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as archive:
            with self.assertRaises(UploadValidationError):
                safe_extract_zip(archive, tmp_dir, max_total_size=8)

    def test_safe_extract_zip_rejects_entry_count_limit(self) -> None:
        archive_bytes = _build_zip(
            [
                ("src/main/java/A.java", b"class A {}"),
                ("src/main/java/B.java", b"class B {}"),
            ]
        )

        with tempfile.TemporaryDirectory() as tmp_dir, zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as archive:
            with self.assertRaises(UploadValidationError):
                safe_extract_zip(archive, tmp_dir, max_entries=1)

    def test_safe_extract_zip_rejects_compression_ratio_limit(self) -> None:
        archive_bytes = _build_zip(
            [("src/main/java/Compressed.java", b"A" * 4096)],
            compression=zipfile.ZIP_DEFLATED,
        )

        with tempfile.TemporaryDirectory() as tmp_dir, zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as archive:
            with self.assertRaises(UploadValidationError):
                safe_extract_zip(archive, tmp_dir, max_compression_ratio=2.0)


if __name__ == "__main__":
    unittest.main()
