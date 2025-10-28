from fastapi import APIRouter, UploadFile, File
from fastapi.responses import JSONResponse
import os
import shutil
import zipfile
import aiofiles

from codegraph.ingestion.utils import safe_extract_zip, find_java_root
from codegraph.ingestion.service import ingest
from codegraph.embedding.service import EmbeddingService
from api.models.validation import UploadResponse
from codegraph.config import UPLOAD_DIR

router = APIRouter()

@router.post("/upload", response_model=UploadResponse)
async def upload_zip(file: UploadFile = File(...)):
    if not file.filename or not file.filename.endswith(".zip"):
        return JSONResponse(content={"error": "Only zip files allowed"}, status_code=400)
    # Clean and extract
    if os.path.exists(UPLOAD_DIR):
        shutil.rmtree(UPLOAD_DIR)
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    zip_path = os.path.join(UPLOAD_DIR, "code.zip")
    async with aiofiles.open(zip_path, "wb") as f:
        content = await file.read()
        await f.write(content)
    with zipfile.ZipFile(zip_path, "r") as zip_ref:
        safe_extract_zip(zip_ref, UPLOAD_DIR)
    java_root = find_java_root(UPLOAD_DIR)
    if java_root is None:
        return JSONResponse(content={"error": "Java root directory not found in uploaded ZIP."}, status_code=400)
    ingest(java_root)
    EmbeddingService.build_embeddings()
    return UploadResponse(status="Codebase processed!", java_root=java_root)
