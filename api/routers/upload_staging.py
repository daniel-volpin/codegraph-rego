from __future__ import annotations

import os
import pathlib
import shutil
import uuid
import zipfile

import aiofiles
from fastapi import UploadFile

from codegraph.config import settings
from codegraph.ingestion.git_source import clone_repository
from codegraph.ingestion.utils import UploadValidationError, find_java_roots, safe_extract_zip

UPLOAD_CHUNK_SIZE = 1024 * 1024


def workspace_parent_dir(upload_dir: str | None = None) -> str:
    target = upload_dir if upload_dir is not None else settings.upload_dir
    parent_dir = os.path.dirname(os.path.abspath(target))
    os.makedirs(parent_dir, exist_ok=True)
    return parent_dir


def unique_workspace_dir(prefix: str, upload_dir: str | None = None) -> str:
    parent_dir = workspace_parent_dir(upload_dir)
    for _ in range(10):
        path = os.path.join(parent_dir, f"{prefix}{uuid.uuid4().hex}")
        try:
            os.mkdir(path)
            return path
        except FileExistsError:
            continue
    raise RuntimeError(f"Unable to allocate workspace directory with prefix {prefix!r}")


def stage_upload_archive(file_name: str, upload_dir: str | None = None) -> tuple[str, str]:
    staging_dir = unique_workspace_dir(".upload_staging_", upload_dir)
    zip_path = os.path.join(staging_dir, file_name)
    return staging_dir, zip_path


def swap_workspace(staging_dir: str, upload_dir: str | None = None) -> str | None:
    target = upload_dir if upload_dir is not None else settings.upload_dir
    target_dir = os.path.abspath(target)
    parent_dir = workspace_parent_dir(target)
    backup_dir = None
    if os.path.exists(target_dir):
        backup_dir = os.path.join(parent_dir, f".upload_backup_{uuid.uuid4().hex}")
        os.replace(target_dir, backup_dir)
    try:
        os.replace(staging_dir, target_dir)
    except OSError:
        if backup_dir is not None:
            os.replace(backup_dir, target_dir)
        raise
    pathlib.Path(target_dir, ".gitkeep").touch(exist_ok=True)
    return backup_dir


def restore_workspace(backup_dir: str | None, upload_dir: str | None = None) -> None:
    target = upload_dir if upload_dir is not None else settings.upload_dir
    target_dir = os.path.abspath(target)
    if os.path.exists(target_dir):
        shutil.rmtree(target_dir)
    if backup_dir and os.path.exists(backup_dir):
        os.replace(backup_dir, target_dir)


def cleanup_dir(path: str | None) -> None:
    if path and os.path.exists(path):
        shutil.rmtree(path)


async def stream_upload_to_disk(
    file: UploadFile,
    zip_path: str,
    max_archive_size_bytes: int | None = None,
) -> None:
    total_bytes = 0
    max_size = max_archive_size_bytes if max_archive_size_bytes is not None else settings.upload_max_archive_size_bytes
    async with aiofiles.open(zip_path, "wb") as handle:
        while True:
            chunk = await file.read(UPLOAD_CHUNK_SIZE)
            if not chunk:
                break
            total_bytes += len(chunk)
            if total_bytes > max_size:
                raise UploadValidationError(
                    f"Uploaded archive exceeds size limit ({total_bytes} > {max_size})"
                )
            await handle.write(chunk)


def extract_zip_sync(
    zip_path: str,
    staging_dir: str,
    *,
    max_file_size: int | None = None,
    max_total_size: int | None = None,
    max_entries: int | None = None,
    max_compression_ratio: float | None = None,
    extract_fn=None,
) -> None:
    extract = extract_fn or safe_extract_zip
    with zipfile.ZipFile(zip_path, "r") as zip_ref:
        extract(
            zip_ref,
            staging_dir,
            max_file_size=max_file_size if max_file_size is not None else settings.upload_max_member_size_bytes,
            max_total_size=max_total_size if max_total_size is not None else settings.upload_max_extracted_size_bytes,
            max_entries=max_entries if max_entries is not None else settings.upload_max_archive_entries,
            max_compression_ratio=max_compression_ratio if max_compression_ratio is not None else settings.upload_max_compression_ratio,
        )


def clone_into_staging(repo_url: str, ref: str | None, upload_dir: str | None = None) -> tuple[str, list[str]]:
    staging_dir = unique_workspace_dir(".clone_staging_", upload_dir)
    try:
        clone_repository(repo_url, staging_dir, ref=ref)
        java_roots = find_java_roots(staging_dir)
        if not java_roots:
            raise UploadValidationError("No src/main/java root found in the repository.")
        return staging_dir, [os.path.relpath(root, staging_dir) for root in java_roots]
    except Exception:
        cleanup_dir(staging_dir)
        raise


def final_java_roots(java_root_relatives: list[str], upload_dir: str | None = None) -> list[str]:
    target = upload_dir if upload_dir is not None else settings.upload_dir
    upload_root = os.path.abspath(target)
    return [os.path.join(upload_root, relative) for relative in java_root_relatives]
