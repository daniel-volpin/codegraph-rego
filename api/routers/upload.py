from fastapi import APIRouter, UploadFile, File
from fastapi.responses import JSONResponse
import os
import shutil
import zipfile
import aiofiles

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


@router.post("/upload", response_model=UploadResponse)
async def upload_zip(file: UploadFile = File(...)):
    start_progress("upload", "Validating upload…", 2.0)
    if not file.filename or not file.filename.endswith(".zip"):
        error_progress("Only zip files allowed")
        return JSONResponse(content={"error": "Only zip files allowed"}, status_code=400)
    try:
        if os.path.exists(UPLOAD_DIR):
            shutil.rmtree(UPLOAD_DIR)
        os.makedirs(UPLOAD_DIR, exist_ok=True)
        update_progress("upload", "Saving archive…", 5.0)
        zip_path = os.path.join(UPLOAD_DIR, "code.zip")
        async with aiofiles.open(zip_path, "wb") as f:
            content = await file.read()
            await f.write(content)
        update_progress("upload", "Extracting archive…", 12.0)
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            safe_extract_zip(zip_ref, UPLOAD_DIR)
    except zipfile.BadZipFile:
        error_progress("Uploaded file is not a valid ZIP archive.")
        return JSONResponse(content={"error": "Uploaded file is not a valid ZIP archive."}, status_code=400)
    except Exception as exc:
        error_progress(f"Failed to prepare upload: {exc}")
        return JSONResponse(content={"error": f"Failed to prepare upload: {exc}"}, status_code=500)
    update_progress("upload", "Locating Java root…", 18.0)
    java_root = find_java_root(UPLOAD_DIR)
    if java_root is None:
        error_progress("Java root directory not found in uploaded ZIP.")
        return JSONResponse(content={"error": "Java root directory not found in uploaded ZIP."}, status_code=400)
    try:
        update_progress("upload", "Resetting uploaded graph…", 20.0)
        purge_workspace_entities(os.path.abspath(UPLOAD_DIR))
        ingest(java_root, progress_callback=update_progress, sync=True)
        EmbeddingService.build_embeddings(progress_callback=update_progress)
    except Exception as exc:
        error_progress(f"Processing failed: {exc}")
        return JSONResponse(content={"error": f"Processing failed: {exc}"}, status_code=500)
    complete_progress("Codebase processed!")
    return UploadResponse(status="Codebase processed!", java_root=java_root)


@router.get("/upload/status", response_model=UploadStatusResponse)
async def upload_status():
    return UploadStatusResponse(**get_progress())
