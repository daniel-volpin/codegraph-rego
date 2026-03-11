import os
import shutil
import tempfile
import zipfile

import aiofiles
from fastapi import APIRouter, File, UploadFile
from fastapi.responses import JSONResponse

from codegraph.ingestion.utils import safe_extract_zip, find_java_root
from codegraph.ingestion.service import ingest, purge_workspace_entities
from codegraph.embedding.service import EmbeddingService
from api.models.validation import UploadResponse, UploadStatusResponse
from codegraph.config import UPLOAD_DIR
from codegraph.common.progress import (
    start_progress,
    update_progress,
    complete_progress,
    error_progress,
    get_progress,
)

router = APIRouter()


def _workspace_parent_dir() -> str:
    parent_dir = os.path.dirname(os.path.abspath(UPLOAD_DIR))
    os.makedirs(parent_dir, exist_ok=True)
    return parent_dir


def _stage_upload_archive(file_name: str, file_content: bytes) -> tuple[str, str]:
    parent_dir = _workspace_parent_dir()
    staging_dir = tempfile.mkdtemp(prefix=".upload_staging_", dir=parent_dir)
    zip_path = os.path.join(staging_dir, file_name)
    return staging_dir, zip_path


def _swap_workspace(staging_dir: str) -> str | None:
    target_dir = os.path.abspath(UPLOAD_DIR)
    parent_dir = _workspace_parent_dir()
    backup_dir = None
    if os.path.exists(target_dir):
        backup_dir = tempfile.mkdtemp(prefix=".upload_backup_", dir=parent_dir)
        os.rmdir(backup_dir)
        os.replace(target_dir, backup_dir)
    os.replace(staging_dir, target_dir)
    return backup_dir


def _restore_workspace(backup_dir: str | None) -> None:
    target_dir = os.path.abspath(UPLOAD_DIR)
    if os.path.exists(target_dir):
        shutil.rmtree(target_dir)
    if backup_dir and os.path.exists(backup_dir):
        os.replace(backup_dir, target_dir)


def _cleanup_dir(path: str | None) -> None:
    if path and os.path.exists(path):
        shutil.rmtree(path)


@router.post("/upload", response_model=UploadResponse)
async def upload_zip(file: UploadFile = File(...)):
    start_progress("upload", "Validating upload…", 2.0)
    if not file.filename or not file.filename.endswith(".zip"):
        error_progress("Only zip files allowed")
        return JSONResponse(content={"error": "Only zip files allowed"}, status_code=400)
    staging_dir = None
    backup_dir = None
    try:
        update_progress("upload", "Saving archive…", 5.0)
        content = await file.read()
        staging_dir, zip_path = _stage_upload_archive("code.zip", content)
        async with aiofiles.open(zip_path, "wb") as f:
            await f.write(content)
        update_progress("upload", "Extracting archive…", 12.0)
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            safe_extract_zip(zip_ref, staging_dir)
    except zipfile.BadZipFile:
        _cleanup_dir(staging_dir)
        error_progress("Uploaded file is not a valid ZIP archive.")
        return JSONResponse(content={"error": "Uploaded file is not a valid ZIP archive."}, status_code=400)
    except Exception as exc:
        _cleanup_dir(staging_dir)
        error_progress(f"Failed to prepare upload: {exc}")
        return JSONResponse(content={"error": f"Failed to prepare upload: {exc}"}, status_code=500)
    update_progress("upload", "Locating Java root…", 18.0)
    java_root = find_java_root(staging_dir)
    if java_root is None:
        _cleanup_dir(staging_dir)
        error_progress("Java root directory not found in uploaded ZIP.")
        return JSONResponse(content={"error": "Java root directory not found in uploaded ZIP."}, status_code=400)
    java_root_relative = os.path.relpath(java_root, staging_dir)
    try:
        update_progress("upload", "Replacing workspace…", 19.0)
        backup_dir = _swap_workspace(staging_dir)
        staging_dir = None
        update_progress("upload", "Resetting uploaded graph…", 20.0)
        purge_workspace_entities(os.path.abspath(UPLOAD_DIR))
        final_java_root = os.path.join(os.path.abspath(UPLOAD_DIR), java_root_relative)
        ingest(final_java_root, progress_callback=update_progress, sync=True)
        EmbeddingService.build_embeddings(progress_callback=update_progress)
    except Exception as exc:
        restore_error = None
        try:
            update_progress("upload", "Restoring previous workspace…", 21.0)
            _restore_workspace(backup_dir)
            backup_dir = None
            if os.path.exists(os.path.abspath(UPLOAD_DIR)):
                restored_java_root = find_java_root(os.path.abspath(UPLOAD_DIR))
                purge_workspace_entities(os.path.abspath(UPLOAD_DIR))
                if restored_java_root is not None:
                    ingest(restored_java_root, progress_callback=update_progress, sync=True)
                    EmbeddingService.build_embeddings(progress_callback=update_progress)
        except Exception as restore_exc:  # pragma: no cover - defensive fallback
            restore_error = restore_exc
        finally:
            _cleanup_dir(staging_dir)
            _cleanup_dir(backup_dir)
        if restore_error is not None:
            error_progress(f"Processing failed and restore failed: {exc}; restore error: {restore_error}")
            return JSONResponse(
                content={"error": f"Processing failed: {exc}. Restore also failed: {restore_error}"},
                status_code=500,
            )
        error_progress(f"Processing failed: {exc}")
        return JSONResponse(content={"error": f"Processing failed: {exc}"}, status_code=500)
    _cleanup_dir(backup_dir)
    complete_progress("Codebase processed!")
    return UploadResponse(status="Codebase processed!", java_root=os.path.join(os.path.abspath(UPLOAD_DIR), java_root_relative))


@router.get("/upload/status", response_model=UploadStatusResponse)
async def upload_status():
    return UploadStatusResponse(**get_progress())
