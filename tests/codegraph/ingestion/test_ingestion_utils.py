from __future__ import annotations

import io
import os
import zipfile
from pathlib import Path
from typing import Any

import pytest

from codegraph.ingestion.utils import UploadValidationError, find_java_roots, safe_extract_zip


def build_zip(entries: list[tuple[str, bytes]], compression: int = zipfile.ZIP_STORED) -> bytes:
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w", compression=compression) as archive:
        for path, content in entries:
            archive.writestr(path, content)
    return payload.getvalue()


def build_symlink_zip() -> bytes:
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w") as archive:
        link_info = zipfile.ZipInfo("escape")
        link_info.external_attr = (0o120777 << 16) | 0xA000
        archive.writestr(link_info, "/etc/passwd")
        archive.writestr("src/main/java/A.java", b"class A {}")
    return payload.getvalue()


def test_find_java_roots_returns_sorted_roots(tmp_path: Path) -> None:
    (tmp_path / "z-module" / "src" / "main" / "java").mkdir(parents=True)
    (tmp_path / "a-module" / "src" / "main" / "java").mkdir(parents=True)

    roots = find_java_roots(tmp_path.as_posix())

    assert roots == [
        os.path.abspath(tmp_path / "a-module" / "src" / "main" / "java"),
        os.path.abspath(tmp_path / "z-module" / "src" / "main" / "java"),
    ]


@pytest.mark.parametrize(
    ("archive_bytes", "kwargs"),
    [
        (
            build_zip(
                [
                    ("src/main/java/A.java", b"class A {}"),
                    ("src/main/java/B.java", b"class B {}"),
                ]
            ),
            {"max_total_size": 8},
        ),
        (
            build_zip(
                [
                    ("src/main/java/A.java", b"class A {}"),
                    ("src/main/java/B.java", b"class B {}"),
                ]
            ),
            {"max_entries": 1},
        ),
        (
            build_zip([("src/main/java/Compressed.java", b"A" * 4096)], compression=zipfile.ZIP_DEFLATED),
            {"max_compression_ratio": 2.0},
        ),
    ],
)
def test_safe_extract_zip_rejects_invalid_archives(
    tmp_path: Path,
    archive_bytes: bytes,
    kwargs: dict[str, Any],
) -> None:
    with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as archive:
        with pytest.raises(UploadValidationError):
            safe_extract_zip(archive, tmp_path.as_posix(), **kwargs)


def test_safe_extract_zip_skips_symlink_member(tmp_path: Path) -> None:
    with zipfile.ZipFile(io.BytesIO(build_symlink_zip()), "r") as archive:
        safe_extract_zip(archive, tmp_path.as_posix())

    assert not os.path.lexists(tmp_path / "escape")
    assert (tmp_path / "src/main/java/A.java").is_file()


def test_safe_extract_zip_skips_traversal_entry(tmp_path: Path) -> None:
    archive_bytes = build_zip(
        [
            ("../escape.txt", b"owned"),
            ("src/main/java/A.java", b"class A {}"),
        ]
    )

    with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as archive:
        safe_extract_zip(archive, tmp_path.as_posix())

    parent_escape = tmp_path.resolve().parent / "escape.txt"
    assert not parent_escape.exists()
    assert (tmp_path / "src/main/java/A.java").is_file()
