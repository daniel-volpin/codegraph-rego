import asyncio
import logging
import os
import zipfile
from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import APIRouter, File, Header, Query, Request, UploadFile
from fastapi.responses import JSONResponse, StreamingResponse

from api.models.validation import GitIngestRequest, UploadResponse, UploadStatusResponse
from api.routers.upload_staging import (
    cleanup_dir as _cleanup_dir,
)
from api.routers.upload_staging import (
    clone_into_staging as _clone_into_staging,
)
from api.routers.upload_staging import (
    extract_zip_sync as _extract_zip_sync,
)
from api.routers.upload_staging import (
    final_java_roots as _final_java_roots,
)
from api.routers.upload_staging import (
    restore_workspace as _restore_workspace,
)
from api.routers.upload_staging import (
    stage_upload_archive as _stage_upload_archive,
)
from api.routers.upload_staging import (
    stream_upload_to_disk as _stream_upload_to_disk,
)
from api.routers.upload_staging import (
    swap_workspace as _swap_workspace,
)
from api.routers.upload_stream import upload_status_event_stream
from codegraph.common.progress import (
    complete_progress,
    error_progress,
    get_progress,
    start_progress,
    update_progress,
)
from codegraph.common.workspace_lock import async_workspace_mutation_guard
from codegraph.config import settings
from codegraph.embedding.service import EmbeddingService
from codegraph.ingestion.service import (
    WorkspacePublication,
    deactivate_other_workspaces,
    ingest,
    rollback_workspace_revision,
)
from codegraph.ingestion.utils import UploadValidationError, find_java_roots, safe_extract_zip

LOGGER = logging.getLogger(__name__)
router = APIRouter()

_SSE_HEARTBEAT_INTERVAL_S = 5.0
_SSE_TERMINAL_GRACE_S = 0.5


def _error_response(message: str, request_id: str, status_code: int) -> JSONResponse:
    error_progress(message)
    return JSONResponse(content={"error": message, "request_id": request_id}, status_code=status_code)


def _ingest_upload_workspace(upload_root: str, java_roots: list[str]) -> WorkspacePublication:
    return ingest(upload_root, progress_callback=update_progress, source_roots=java_roots)


def _build_upload_embeddings() -> None:
    EmbeddingService.build_embeddings(progress_callback=update_progress)


def _extract_zip_helper(zip_path: str, staging_dir: str) -> None:
    _extract_zip_sync(
        zip_path,
        staging_dir,
        max_file_size=settings.upload_max_member_size_bytes,
        max_total_size=settings.upload_max_extracted_size_bytes,
        max_entries=settings.upload_max_archive_entries,
        max_compression_ratio=settings.upload_max_compression_ratio,
        extract_fn=safe_extract_zip,
    )


async def _prepare_staged_upload(file: UploadFile, request_id: str) -> tuple[str, list[str]] | JSONResponse:
    staging_dir: str | None = None
    zip_path: str | None = None
    try:
        update_progress("upload", "Saving archive…", 5.0)
        staging_dir, zip_path = _stage_upload_archive("code.zip", settings.upload_dir)
        await _stream_upload_to_disk(file, zip_path, settings.upload_max_archive_size_bytes)
        update_progress("upload", "Extracting archive…", 12.0)
        await asyncio.to_thread(_extract_zip_helper, zip_path, staging_dir)
        if os.path.exists(zip_path):
            os.remove(zip_path)

        update_progress("upload", "Locating Java roots…", 18.0)
        java_roots = await asyncio.to_thread(find_java_roots, staging_dir)
        if java_roots:
            return staging_dir, [os.path.relpath(java_root, staging_dir) for java_root in java_roots]
        await asyncio.to_thread(_cleanup_dir, staging_dir)
        return _error_response("Java root directories not found in uploaded ZIP.", request_id, 400)
    except zipfile.BadZipFile:
        _cleanup_dir(staging_dir)
        return _error_response("Uploaded file is not a valid ZIP archive.", request_id, 400)
    except UploadValidationError as exc:
        _cleanup_dir(staging_dir)
        return _error_response(str(exc), request_id, 400)
    except Exception as exc:
        _cleanup_dir(staging_dir)
        return _error_response(f"Failed to prepare upload: {exc}", request_id, 500)


async def _restore_previous_workspace(
    backup_dir: str | None, *, publication: WorkspacePublication | None = None,
) -> Exception | None:
    try:
        update_progress("upload", "Restoring previous workspace…", 21.0)
        await asyncio.to_thread(_restore_workspace, backup_dir, settings.upload_dir)
        if publication is not None:
            await asyncio.to_thread(rollback_workspace_revision, publication)
        return None
    except Exception as restore_exc:  # pragma: no cover - defensive fallback
        return restore_exc


async def _handle_workspace_processing_error(
    exc: Exception,
    *,
    request_id: str,
    staging_dir: str | None,
    backup_dir: str | None,
    publication: WorkspacePublication | None = None,
) -> JSONResponse:
    restore_error = (
        await _restore_previous_workspace(backup_dir, publication=publication)
        if staging_dir is None else None
    )
    await asyncio.to_thread(_cleanup_dir, staging_dir)
    if restore_error is not None:
        return _error_response(
            f"Processing failed: {exc}. Restore also failed: {restore_error}. Recovery directory: {backup_dir}",
            request_id,
            500,
        )
    await asyncio.to_thread(_cleanup_dir, backup_dir)
    return _error_response(f"Processing failed: {exc}", request_id, 500)


async def _publish_staged_workspace(
    staging_dir: str, java_root_relatives: list[str], request_id: str,
):
    backup_dir = None
    publication = None
    update_progress("upload", "Waiting for workspace publication slot…", 19.0)
    async with async_workspace_mutation_guard():
        try:
            update_progress("upload", "Replacing workspace…", 19.0)
            backup_dir = await asyncio.to_thread(_swap_workspace, staging_dir, settings.upload_dir)
            staging_dir = None
            update_progress("upload", "Publishing uploaded graph revision…", 20.0)
            upload_root = os.path.abspath(settings.upload_dir)
            publication = await asyncio.to_thread(
                _ingest_upload_workspace, upload_root, _final_java_roots(java_root_relatives, settings.upload_dir),
            )
            dropped = await asyncio.to_thread(deactivate_other_workspaces, publication.workspace_id)
            if dropped:
                LOGGER.info("Deactivated %d previously active workspace(s): %s", len(dropped), ", ".join(dropped))
            await asyncio.to_thread(_build_upload_embeddings)
        except Exception as exc:
            return await _handle_workspace_processing_error(
                exc,
                request_id=request_id,
                staging_dir=staging_dir,
                backup_dir=backup_dir,
                publication=publication,
            )
    await asyncio.to_thread(_cleanup_dir, backup_dir)
    complete_progress("Codebase processed!")
    final_roots = _final_java_roots(java_root_relatives, settings.upload_dir)
    return UploadResponse(
        status="Codebase processed!",
        java_root=final_roots[0],
        java_roots=final_roots,
        request_id=request_id,
    )


@router.post("/upload", response_model=UploadResponse)
async def upload_zip(
    file: UploadFile = File(...),
    request_id_header: Annotated[str | None, Header(alias="X-Request-Id")] = None,
):
    request_id = start_progress(
        "upload",
        "Validating upload…",
        2.0,
        request_id=request_id_header.strip() if request_id_header and request_id_header.strip() else None,
    )
    if not file.filename or not file.filename.endswith(".zip"):
        return _error_response("Only zip files allowed", request_id, 400)

    prepared = await _prepare_staged_upload(file, request_id)
    if isinstance(prepared, JSONResponse):
        return prepared

    staging_dir, java_root_relatives = prepared
    return await _publish_staged_workspace(staging_dir, java_root_relatives, request_id)


@router.post("/upload/git", response_model=UploadResponse)
async def upload_from_git(
    payload: GitIngestRequest,
    request_id_header: Annotated[str | None, Header(alias="X-Request-Id")] = None,
):
    request_id = start_progress(
        "upload",
        "Validating repository URL…",
        2.0,
        request_id=request_id_header.strip() if request_id_header and request_id_header.strip() else None,
    )
    try:
        update_progress("upload", "Cloning repository…", 5.0)
        staging_dir, java_root_relatives = await asyncio.to_thread(
            _clone_into_staging, payload.repo_url, payload.ref, settings.upload_dir,
        )
    except UploadValidationError as exc:
        return _error_response(str(exc), request_id, 400)
    except Exception as exc:
        return _error_response(f"Failed to clone repository: {exc}", request_id, 500)
    return await _publish_staged_workspace(staging_dir, java_root_relatives, request_id)


@router.get("/upload/status", response_model=UploadStatusResponse)
async def upload_status(
    request_id: str | None = Query(
        default=None,
        description=(
            "Per-request progress key returned by POST /upload. When omitted, "
            "returns the latest-started job's state for backward compatibility."
        ),
    ),
):
    return UploadStatusResponse(**get_progress(request_id=request_id))


async def _upload_status_event_stream(request: Request, request_id: str | None) -> AsyncIterator[bytes]:
    async for chunk in upload_status_event_stream(
        request,
        request_id,
        heartbeat_interval_provider=lambda: _SSE_HEARTBEAT_INTERVAL_S,
        terminal_grace_provider=lambda: _SSE_TERMINAL_GRACE_S,
    ):
        yield chunk


@router.get("/upload/status/stream")
async def upload_status_stream(
    request: Request,
    request_id: str | None = Query(
        default=None,
        description=(
            "Per-request progress key returned by POST /upload. When omitted, "
            "streams the latest-started job's state for backward compatibility."
        ),
    ),
):
    return StreamingResponse(
        _upload_status_event_stream(request, request_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )

