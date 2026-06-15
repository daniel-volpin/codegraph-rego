import asyncio
import json
import os
import shutil
import tempfile
import zipfile
from collections.abc import AsyncIterator

import aiofiles
from fastapi import APIRouter, File, Query, Request, UploadFile
from fastapi.responses import JSONResponse, StreamingResponse

from api.models.validation import UploadResponse, UploadStatusResponse
from codegraph.common.progress import (
    complete_progress,
    error_progress,
    get_progress,
    register_state_change_listener,
    start_progress,
    update_progress,
)
from codegraph.config import settings
from codegraph.embedding.service import EmbeddingService
from codegraph.ingestion.service import ingest, purge_workspace_entities
from codegraph.ingestion.utils import UploadValidationError, find_java_roots, safe_extract_zip

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


def _error_response(message: str, request_id: str, status_code: int) -> JSONResponse:
    error_progress(message)
    return JSONResponse(content={"error": message, "request_id": request_id}, status_code=status_code)


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


def _extract_zip_sync(zip_path: str, staging_dir: str) -> None:
    with zipfile.ZipFile(zip_path, "r") as zip_ref:
        safe_extract_zip(
            zip_ref,
            staging_dir,
            max_file_size=settings.upload_max_member_size_bytes,
            max_total_size=settings.upload_max_extracted_size_bytes,
            max_entries=settings.upload_max_archive_entries,
            max_compression_ratio=settings.upload_max_compression_ratio,
        )


async def _prepare_staged_upload(file: UploadFile, request_id: str) -> tuple[str, list[str]] | JSONResponse:
    staging_dir: str | None = None
    zip_path: str | None = None
    try:
        update_progress("upload", "Saving archive…", 5.0)
        staging_dir, zip_path = _stage_upload_archive("code.zip")
        await _stream_upload_to_disk(file, zip_path)
        update_progress("upload", "Extracting archive…", 12.0)
        await asyncio.to_thread(_extract_zip_sync, zip_path, staging_dir)
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


def _final_java_roots(java_root_relatives: list[str]) -> list[str]:
    upload_root = os.path.abspath(settings.upload_dir)
    return [os.path.join(upload_root, relative) for relative in java_root_relatives]


async def _restore_previous_workspace(backup_dir: str | None) -> Exception | None:
    try:
        update_progress("upload", "Restoring previous workspace…", 21.0)
        await asyncio.to_thread(_restore_workspace, backup_dir)
        upload_root = os.path.abspath(settings.upload_dir)
        if not os.path.exists(upload_root):
            return None
        restored_java_roots = await asyncio.to_thread(find_java_roots, upload_root)
        await asyncio.to_thread(purge_workspace_entities, upload_root)
        if restored_java_roots:
            await asyncio.to_thread(_ingest_java_roots, restored_java_roots)
        return None
    except Exception as restore_exc:  # pragma: no cover - defensive fallback
        return restore_exc


async def _handle_workspace_processing_error(
    exc: Exception,
    *,
    request_id: str,
    staging_dir: str | None,
    backup_dir: str | None,
) -> JSONResponse:
    restore_error = await _restore_previous_workspace(backup_dir)
    await asyncio.to_thread(_cleanup_dir, staging_dir)
    await asyncio.to_thread(_cleanup_dir, backup_dir)
    if restore_error is not None:
        return _error_response(
            f"Processing failed: {exc}. Restore also failed: {restore_error}",
            request_id,
            500,
        )
    return _error_response(f"Processing failed: {exc}", request_id, 500)


@router.post("/upload", response_model=UploadResponse)
async def upload_zip(file: UploadFile = File(...)):
    # request_id is echoed on every response so the caller can poll
    # GET /upload/status?request_id=<id> for its own upload's progress.
    request_id = start_progress("upload", "Validating upload…", 2.0)
    if not file.filename or not file.filename.endswith(".zip"):
        return _error_response("Only zip files allowed", request_id, 400)

    prepared = await _prepare_staged_upload(file, request_id)
    if isinstance(prepared, JSONResponse):
        return prepared

    staging_dir, java_root_relatives = prepared
    backup_dir = None
    try:
        update_progress("upload", "Replacing workspace…", 19.0)
        backup_dir = await asyncio.to_thread(_swap_workspace, staging_dir)
        staging_dir = None
        update_progress("upload", "Resetting uploaded graph…", 20.0)
        await asyncio.to_thread(purge_workspace_entities, os.path.abspath(settings.upload_dir))
        await asyncio.to_thread(_ingest_java_roots, _final_java_roots(java_root_relatives))
    except Exception as exc:
        return await _handle_workspace_processing_error(
            exc,
            request_id=request_id,
            staging_dir=staging_dir,
            backup_dir=backup_dir,
        )
    await asyncio.to_thread(_cleanup_dir, backup_dir)
    complete_progress("Codebase processed!")
    final_java_roots = _final_java_roots(java_root_relatives)
    return UploadResponse(
        status="Codebase processed!",
        java_root=final_java_roots[0],
        java_roots=final_java_roots,
        request_id=request_id,
    )


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


# Tunables for the SSE stream. Held at module scope so tests can patch them
# to keep test runs fast without changing prod cadence.
_SSE_HEARTBEAT_INTERVAL_S = 5.0  # max gap between any bytes on the wire
_SSE_TERMINAL_GRACE_S = 0.5  # let the last event flush before closing


async def _upload_status_event_stream(
    request: Request,
    request_id: str | None,
) -> AsyncIterator[bytes]:
    """Yield SSE bytes until the underlying job completes or the client disconnects.

    Push-driven: the loop sleeps on an ``asyncio.Event`` that the progress
    module sets whenever a state mutation matching our ``request_id``
    occurs. The wake is scheduled across the thread boundary via
    ``loop.call_soon_threadsafe`` because progress writers run on worker
    threads (``asyncio.to_thread`` → sync ingestion callbacks).

    A heartbeat timeout (``_SSE_HEARTBEAT_INTERVAL_S``) doubles as the
    interval at which we re-poll ``request.is_disconnected()`` so a worker
    is never held more than that long after the client closes the tab.

    When ``complete`` flips to True, sends a final ``event: complete`` and
    returns. The whole stream runs inside the auto-instrumented FastAPI
    span so the upload's traceparent (if propagated by the client) chains
    the stream request to the originating ``POST /upload`` span.
    """
    loop = asyncio.get_running_loop()
    state_changed = asyncio.Event()

    def _on_state_change(changed_rid: str | None) -> None:
        # request_id=None means "tail the latest job"; accept every event.
        # An explicit request_id only wakes on matching mutations.
        if request_id is None or changed_rid == request_id:
            try:
                loop.call_soon_threadsafe(state_changed.set)
            except RuntimeError:
                # Loop is closing; the finally-block in the consumer will
                # unregister us shortly. Drop the wake.
                pass

    unregister = register_state_change_listener(_on_state_change)
    last_payload: str | None = None
    try:
        while True:
            if await request.is_disconnected():
                return
            # Clear the flag BEFORE reading state. If a writer fires
            # set() between get_progress() and a later clear(), the signal
            # would be lost and the next wait() would sleep until the
            # heartbeat. Clearing first means any subsequent set() — from
            # a writer that races our read — is preserved for the wait()
            # below and we wake immediately on the next iteration.
            state_changed.clear()
            state = get_progress(request_id=request_id)
            payload = json.dumps(state, separators=(",", ":"))
            if payload != last_payload:
                yield f"event: status\ndata: {payload}\n\n".encode()
                last_payload = payload
            if state.get("complete"):
                yield f"event: complete\ndata: {payload}\n\n".encode()
                # Brief grace so client buffers flush before the stream closes.
                await asyncio.sleep(_SSE_TERMINAL_GRACE_S)
                return
            # Wait for either: a state change wake, or the heartbeat timeout
            # (at which point we'll loop, re-check disconnect, and emit a
            # keepalive comment if nothing changed).
            try:
                await asyncio.wait_for(state_changed.wait(), timeout=_SSE_HEARTBEAT_INTERVAL_S)
            except asyncio.TimeoutError:
                # SSE comment lines are ignored by EventSource but defeat
                # proxy idle timeouts; cheaper than re-emitting status.
                yield b": heartbeat\n\n"
    finally:
        unregister()


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
    """Server-Sent Events stream of upload progress.

    Browser fallback is automatic: the client (``useUploadStatusStream``)
    falls back to bounded polling on EventSource error.
    """
    return StreamingResponse(
        _upload_status_event_stream(request, request_id),
        media_type="text/event-stream",
        headers={
            # SSE proxies / nginx buffering breaks the streaming semantics.
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )
