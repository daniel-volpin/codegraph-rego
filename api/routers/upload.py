import asyncio
import json
import os
import shutil
import tempfile
import zipfile
from typing import AsyncIterator

import aiofiles
from fastapi import APIRouter, File, Query, Request, UploadFile
from fastapi.responses import JSONResponse, StreamingResponse

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
    register_state_change_listener,
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
    # request_id is echoed on every response so the caller can poll
    # GET /upload/status?request_id=<id> for its own upload's progress.
    request_id = start_progress("upload", "Validating upload…", 2.0)
    if not file.filename or not file.filename.endswith(".zip"):
        error_progress("Only zip files allowed")
        return JSONResponse(
            content={"error": "Only zip files allowed", "request_id": request_id},
            status_code=400,
        )
    staging_dir = None
    backup_dir = None
    zip_path = None
    try:
        update_progress("upload", "Saving archive…", 5.0)
        staging_dir, zip_path = _stage_upload_archive("code.zip")
        await _stream_upload_to_disk(file, zip_path)
        update_progress("upload", "Extracting archive…", 12.0)

        # Open+extract on a single thread; never hold the zip handle
        # across the loop boundary.
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
        return JSONResponse(
            content={"error": "Uploaded file is not a valid ZIP archive.", "request_id": request_id},
            status_code=400,
        )
    except UploadValidationError as exc:
        _cleanup_dir(staging_dir)
        error_progress(str(exc))
        return JSONResponse(
            content={"error": str(exc), "request_id": request_id},
            status_code=400,
        )
    except Exception as exc:
        _cleanup_dir(staging_dir)
        error_progress(f"Failed to prepare upload: {exc}")
        return JSONResponse(
            content={"error": f"Failed to prepare upload: {exc}", "request_id": request_id},
            status_code=500,
        )
    update_progress("upload", "Locating Java roots…", 18.0)
    java_roots = await asyncio.to_thread(find_java_roots, staging_dir)
    if not java_roots:
        await asyncio.to_thread(_cleanup_dir, staging_dir)
        error_progress("Java root directories not found in uploaded ZIP.")
        return JSONResponse(
            content={"error": "Java root directories not found in uploaded ZIP.", "request_id": request_id},
            status_code=400,
        )
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
                content={
                    "error": f"Processing failed: {exc}. Restore also failed: {restore_error}",
                    "request_id": request_id,
                },
                status_code=500,
            )
        error_progress(f"Processing failed: {exc}")
        return JSONResponse(
            content={"error": f"Processing failed: {exc}", "request_id": request_id},
            status_code=500,
        )
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
                content={
                    "error": f"Processing failed: {exc}. Restore also failed: {restore_error}",
                    "request_id": request_id,
                },
                status_code=500,
            )
        error_progress(f"Processing failed: {exc}")
        return JSONResponse(
            content={"error": f"Processing failed: {exc}", "request_id": request_id},
            status_code=500,
        )
    await asyncio.to_thread(_cleanup_dir, backup_dir)
    complete_progress("Codebase processed!")
    final_java_roots = [
        os.path.join(os.path.abspath(settings.upload_dir), relative) for relative in java_root_relatives
    ]
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
            state = get_progress(request_id=request_id)
            payload = json.dumps(state, separators=(",", ":"))
            if payload != last_payload:
                yield f"event: status\ndata: {payload}\n\n".encode("utf-8")
                last_payload = payload
            if state.get("complete"):
                yield f"event: complete\ndata: {payload}\n\n".encode("utf-8")
                # Brief grace so client buffers flush before the stream closes.
                await asyncio.sleep(_SSE_TERMINAL_GRACE_S)
                return
            # Wait for either: a state change wake, or the heartbeat timeout
            # (at which point we'll loop, re-check disconnect, and emit a
            # keepalive comment if nothing changed).
            state_changed.clear()
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
