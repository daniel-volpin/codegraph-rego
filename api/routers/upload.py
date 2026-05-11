import asyncio
import os
import shutil
import tempfile
import zipfile

import aiofiles
from fastapi import APIRouter, File, UploadFile
from fastapi.responses import JSONResponse

from codegraph.ingestion.utils import UploadValidationError, find_java_roots, safe_extract_zip
from codegraph.ingestion.service import IngestionError, ingest, purge_workspace_entities
from codegraph.embedding.service import EmbeddingService
from api.models.validation import UploadResponse, UploadStatusResponse
from codegraph.config import settings
from codegraph.common.progress import (
    start_progress,
    update_progress,
    complete_progress,
    error_progress,
    get_progress,
)

router = APIRouter()
UPLOAD_CHUNK_SIZE = 1024 * 1024


def _workspace_parent_dir() -> str:
    parent_dir = os.path.dirname(os.path.abspath(settings.upload_dir))
    os.makedirs(parent_dir, exist_ok=True)
    return parent_dir


def _stage_upload_archive(file_name: str) -> tuple[str, str]:
    parent_dir = _workspace_parent_dir()
    staging_dir = tempfile.mkdtemp(prefix=".upload_staging_", dir=parent_dir)
    zip_path = os.path.join(staging_dir, file_name)
    return staging_dir, zip_path


def _swap_workspace(staging_dir: str) -> str | None:
    target_dir = os.path.abspath(settings.upload_dir)
    parent_dir = _workspace_parent_dir()
    backup_dir = None
    if os.path.exists(target_dir):
        backup_dir = tempfile.mkdtemp(prefix=".upload_backup_", dir=parent_dir)
        os.rmdir(backup_dir)
        os.replace(target_dir, backup_dir)
    os.replace(staging_dir, target_dir)
    return backup_dir


def _restore_workspace(backup_dir: str | None) -> None:
    target_dir = os.path.abspath(settings.upload_dir)
    if os.path.exists(target_dir):
        shutil.rmtree(target_dir)
    if backup_dir and os.path.exists(backup_dir):
        os.replace(backup_dir, target_dir)


def _cleanup_dir(path: str | None) -> None:
    if path and os.path.exists(path):
        shutil.rmtree(path)


async def _stream_upload_to_disk(file: UploadFile, zip_path: str) -> None:
    total_bytes = 0
    async with aiofiles.open(zip_path, "wb") as handle:
        while True:
            chunk = await file.read(UPLOAD_CHUNK_SIZE)
            if not chunk:
                break
            total_bytes += len(chunk)
            if total_bytes > settings.upload_max_archive_size_bytes:
                raise UploadValidationError(
                    f"Uploaded archive exceeds size limit ({total_bytes} > {settings.upload_max_archive_size_bytes})"
                )
            await handle.write(chunk)


def _ingest_java_roots(java_roots: list[str]) -> None:
    for java_root in java_roots:
        ingest(java_root, progress_callback=update_progress, sync=False)
    EmbeddingService.build_embeddings(progress_callback=update_progress)


@router.post("/upload", response_model=UploadResponse)
async def upload_zip(file: UploadFile = File(...)):
    start_progress("upload", "Validating upload…", 2.0)
    if not file.filename or not file.filename.endswith(".zip"):
        error_progress("Only zip files allowed")
        return JSONResponse(content={"error": "Only zip files allowed"}, status_code=400)
    staging_dir = None
    backup_dir = None
    zip_path = None
    try:
        update_progress("upload", "Saving archive…", 5.0)
        staging_dir, zip_path = _stage_upload_archive("code.zip")
        await _stream_upload_to_disk(file, zip_path)
        update_progress("upload", "Extracting archive…", 12.0)

        # F08: zip extraction is CPU+I/O bound; hop to a worker thread so the
        # event loop stays responsive. The whole "open zip + safe_extract"
        # pair runs on the thread to avoid holding the zip handle across
        # the loop boundary.
        def _extract_zip_sync() -> None:
            with zipfile.ZipFile(zip_path, "r") as zip_ref:
                safe_extract_zip(
                    zip_ref,
                    staging_dir,
                    max_file_size=settings.upload_max_member_size_bytes,
                    max_total_size=settings.upload_max_extracted_size_bytes,
                    max_entries=settings.upload_max_archive_entries,
                    max_compression_ratio=settings.upload_max_compression_ratio,
                )

        await asyncio.to_thread(_extract_zip_sync)
        if zip_path and os.path.exists(zip_path):
            os.remove(zip_path)
    except zipfile.BadZipFile:
        _cleanup_dir(staging_dir)
        error_progress("Uploaded file is not a valid ZIP archive.")
        return JSONResponse(content={"error": "Uploaded file is not a valid ZIP archive."}, status_code=400)
    except UploadValidationError as exc:
        _cleanup_dir(staging_dir)
        error_progress(str(exc))
        return JSONResponse(content={"error": str(exc)}, status_code=400)
    except Exception as exc:
        _cleanup_dir(staging_dir)
        error_progress(f"Failed to prepare upload: {exc}")
        return JSONResponse(content={"error": f"Failed to prepare upload: {exc}"}, status_code=500)
    update_progress("upload", "Locating Java roots…", 18.0)
    # F08: directory walks, Neo4j writes, FAISS embedding builds, and
    # filesystem renames are all synchronous. Each gets its own thread hop
    # so progress updates between them keep flowing on the event loop.
    java_roots = await asyncio.to_thread(find_java_roots, staging_dir)
    if not java_roots:
        await asyncio.to_thread(_cleanup_dir, staging_dir)
        error_progress("Java root directories not found in uploaded ZIP.")
        return JSONResponse(content={"error": "Java root directories not found in uploaded ZIP."}, status_code=400)
    java_root_relatives = [os.path.relpath(java_root, staging_dir) for java_root in java_roots]
    try:
        update_progress("upload", "Replacing workspace…", 19.0)
        backup_dir = await asyncio.to_thread(_swap_workspace, staging_dir)
        staging_dir = None
        update_progress("upload", "Resetting uploaded graph…", 20.0)
        await asyncio.to_thread(purge_workspace_entities, os.path.abspath(settings.upload_dir))
        final_java_roots = [
            os.path.join(os.path.abspath(settings.upload_dir), relative) for relative in java_root_relatives
        ]
        await asyncio.to_thread(_ingest_java_roots, final_java_roots)
    except IngestionError as exc:
        restore_error = None
        try:
            update_progress("upload", "Restoring previous workspace…", 21.0)
            await asyncio.to_thread(_restore_workspace, backup_dir)
            backup_dir = None
            if os.path.exists(os.path.abspath(settings.upload_dir)):
                restored_java_roots = await asyncio.to_thread(
                    find_java_roots, os.path.abspath(settings.upload_dir)
                )
                await asyncio.to_thread(purge_workspace_entities, os.path.abspath(settings.upload_dir))
                if restored_java_roots:
                    await asyncio.to_thread(_ingest_java_roots, restored_java_roots)
        except Exception as restore_exc:  # pragma: no cover - defensive fallback
            restore_error = restore_exc
        finally:
            await asyncio.to_thread(_cleanup_dir, staging_dir)
            await asyncio.to_thread(_cleanup_dir, backup_dir)
        if restore_error is not None:
            error_progress(f"Processing failed and restore failed: {exc}; restore error: {restore_error}")
            return JSONResponse(
                content={"error": f"Processing failed: {exc}. Restore also failed: {restore_error}"},
                status_code=500,
            )
        error_progress(f"Processing failed: {exc}")
        return JSONResponse(content={"error": f"Processing failed: {exc}"}, status_code=500)
    except Exception as exc:
        restore_error = None
        try:
            update_progress("upload", "Restoring previous workspace…", 21.0)
            await asyncio.to_thread(_restore_workspace, backup_dir)
            backup_dir = None
            if os.path.exists(os.path.abspath(settings.upload_dir)):
                restored_java_roots = await asyncio.to_thread(
                    find_java_roots, os.path.abspath(settings.upload_dir)
                )
                await asyncio.to_thread(purge_workspace_entities, os.path.abspath(settings.upload_dir))
                if restored_java_roots:
                    await asyncio.to_thread(_ingest_java_roots, restored_java_roots)
        except Exception as restore_exc:  # pragma: no cover - defensive fallback
            restore_error = restore_exc
        finally:
            await asyncio.to_thread(_cleanup_dir, staging_dir)
            await asyncio.to_thread(_cleanup_dir, backup_dir)
        if restore_error is not None:
            error_progress(f"Processing failed and restore failed: {exc}; restore error: {restore_error}")
            return JSONResponse(
                content={"error": f"Processing failed: {exc}. Restore also failed: {restore_error}"},
                status_code=500,
            )
        error_progress(f"Processing failed: {exc}")
        return JSONResponse(content={"error": f"Processing failed: {exc}"}, status_code=500)
    await asyncio.to_thread(_cleanup_dir, backup_dir)
    complete_progress("Codebase processed!")
    final_java_roots = [
        os.path.join(os.path.abspath(settings.upload_dir), relative) for relative in java_root_relatives
    ]
    return UploadResponse(
        status="Codebase processed!",
        java_root=final_java_roots[0],
        java_roots=final_java_roots,
    )


@router.get("/upload/status", response_model=UploadStatusResponse)
async def upload_status():
    return UploadStatusResponse(**get_progress())
