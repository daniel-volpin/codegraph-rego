
from fastapi import UploadFile
import zipfile
import shutil
import os
from codegraph.ingestion.utils import safe_extract_zip, find_java_root
from codegraph.embedding.service import EmbeddingService
from codegraph.ingestion.service import ingest
from codegraph.config import UPLOAD_DIR
from pydantic import BaseModel
import logging

logger = logging.getLogger(__name__)

class UploadResponse(BaseModel):
    status: str | None = None
    java_root: str | None = None
    error: str | None = None

def handle_upload(file: UploadFile) -> tuple[UploadResponse, int]:
    if not file.filename or not file.filename.endswith(".zip"):
        return UploadResponse(error="Only zip files allowed"), 400
    # Clean and extract
    if os.path.exists(UPLOAD_DIR):
        shutil.rmtree(UPLOAD_DIR)
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    zip_path = os.path.join(UPLOAD_DIR, "code.zip")
    # Reset file pointer and write bytes to disk
    file.file.seek(0)
    with open(zip_path, "wb") as f:
        f.write(file.file.read())
    try:
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            safe_extract_zip(zip_ref, UPLOAD_DIR)
    except zipfile.BadZipFile:
        logger.error("Uploaded file is not a valid ZIP archive.")
        return UploadResponse(error="bad_zip_file"), 400
    java_root = find_java_root(UPLOAD_DIR)
    if java_root is None:
        logger.error("Java root directory not found in uploaded ZIP.")
        return UploadResponse(error="java_root_not_found"), 400
    try:
        ingest(java_root)
        EmbeddingService.build_embeddings()
    except Exception as e:
        logger.error(f"Processing failed: {e}")
        return UploadResponse(error=f"processing_failed: {e}"), 500
    return UploadResponse(status="Codebase processed!", java_root=java_root), 200
