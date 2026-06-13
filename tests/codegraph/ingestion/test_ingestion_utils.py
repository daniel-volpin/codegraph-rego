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

    def test_safe_extract_zip_skips_symlink_member(self) -> None:
        # Build an archive containing a symlink entry pointing outside dest, plus
        # a normal file. The symlink must be skipped (Zip-Slip protection) while
        # the normal file extracts.
        payload = io.BytesIO()
        with zipfile.ZipFile(payload, "w") as archive:
            link_info = zipfile.ZipInfo("escape")
            # Mark as symlink (S_IFLNK | 0777) in the external attributes.
            link_info.external_attr = (0o120777 << 16) | 0xA000
            archive.writestr(link_info, "/etc/passwd")
            archive.writestr("src/main/java/A.java", b"class A {}")
        archive_bytes = payload.getvalue()

        with tempfile.TemporaryDirectory() as tmp_dir, zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as archive:
            safe_extract_zip(archive, tmp_dir)
            self.assertFalse(os.path.lexists(os.path.join(tmp_dir, "escape")))
            self.assertTrue(os.path.isfile(os.path.join(tmp_dir, "src/main/java/A.java")))

    def test_safe_extract_zip_skips_traversal_entry(self) -> None:
        payload = io.BytesIO()
        with zipfile.ZipFile(payload, "w") as archive:
            archive.writestr("../escape.txt", b"owned")
            archive.writestr("src/main/java/A.java", b"class A {}")
        archive_bytes = payload.getvalue()

        with tempfile.TemporaryDirectory() as tmp_dir, zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as archive:
            safe_extract_zip(archive, tmp_dir)
            parent_escape = os.path.join(os.path.dirname(os.path.realpath(tmp_dir)), "escape.txt")
            self.assertFalse(os.path.exists(parent_escape))
            self.assertTrue(os.path.isfile(os.path.join(tmp_dir, "src/main/java/A.java")))


if __name__ == "__main__":
    unittest.main()
