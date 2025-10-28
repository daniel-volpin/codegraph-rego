from fastapi import UploadFile
import zipfile
import shutil
import os
from codegraph.ingestion.utils import safe_extract_zip, find_java_root
from codegraph.embedding.service import EmbeddingService
from codegraph.ingestion.service import ingest
from codegraph.config import UPLOAD_DIR
from fastapi.responses import JSONResponse
import logging

logger = logging.getLogger(__name__)

def handle_upload(file: UploadFile) -> tuple[dict, int]:
    if not file.filename or not file.filename.endswith(".zip"):
        return {"error": "Only zip files allowed"}, 400
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
        return {"error": "bad_zip_file"}, 400
    java_root = find_java_root(UPLOAD_DIR)
    if java_root is None:
        logger.error("Java root directory not found in uploaded ZIP.")
        return {"error": "java_root_not_found"}, 400
    try:
        ingest(java_root)
        EmbeddingService.build_embeddings()
    except Exception as e:
        logger.error(f"Processing failed: {e}")
        return {"error": f"processing_failed: {e}"}, 500
    return {"status": "Codebase processed!", "java_root": java_root}, 200
