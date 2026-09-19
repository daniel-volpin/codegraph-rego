from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from codegraph.embedding.service import EmbeddingService
from codegraph.ingestion.service import WorkspacePublication, ingest
from codegraph.remediation.editing import unified_diff
from codegraph.remediation.method_key_paths import parse_method_key_relative_path, resolve_workspace_root
from codegraph.remediation.result_models import CompilationResult

LOGGER = logging.getLogger(__name__)


def _unified_diff(before: str, after: str, *, label: str = "method") -> str:
    return unified_diff(before, after, label=label)


def _build_passed(compilation: CompilationResult) -> bool:
    return bool(compilation.get("attempted")) and bool(compilation.get("success"))


def _verification_passed(verification: dict[str, Any]) -> bool:
    return verification.get("status") == "POLICY_PASS"


def _can_commit_apply(mode: str, verification: dict[str, Any], compilation: CompilationResult) -> bool:
    return mode == "apply" and _verification_passed(verification) and _build_passed(compilation)


def _final_status(
    *,
    mode: str,
    verification: dict[str, Any],
    compilation: CompilationResult,
    apply_successful: bool,
    restore_failed: bool,
) -> str:
    if restore_failed:
        return "VERIFICATION_ERROR"
    if verification.get("error"):
        return "VERIFICATION_ERROR"
    if not _build_passed(compilation):
        if compilation.get("attempted"):
            return "BUILD_ERROR"
        return "VERIFICATION_ERROR"
    if not _verification_passed(verification):
        return "VERIFICATION_ERROR"
    if mode == "apply" and not apply_successful:
        return "VERIFICATION_ERROR"
    return "OK"


def _final_error(status: str, verification: dict[str, Any], *, restore_failed: bool) -> str | None:
    if status == "OK":
        return None
    if restore_failed:
        primary_error = verification.get("error")
        rollback_error = "Rollback failed: workspace may be left in candidate state"
        return f"{primary_error}; {rollback_error}" if primary_error else rollback_error
    return verification.get("error") or "Apply verification failed"


def _restore_file(
    resolved_path: Path,
    original_bytes: bytes,
    expected_current_bytes: bytes | None,
) -> bool:
    try:
        if expected_current_bytes is not None and resolved_path.read_bytes() != expected_current_bytes:
            LOGGER.warning(
                "Refusing to restore %s because it changed after remediation wrote the candidate.", resolved_path
            )
            return False
        resolved_path.write_bytes(original_bytes)
        return True
    except OSError as exc:  # pragma: no cover - filesystem guard
        LOGGER.warning("Failed to restore original content for %s: %s", resolved_path, exc)
        return False


def _should_restore(mode: str, apply_successful: bool) -> bool:
    return mode != "apply" or not apply_successful


def _method_key_relative_path(method_key: str) -> Path:
    relative = parse_method_key_relative_path(method_key)
    if relative is None:
        raise ValueError("invalid_method_key")
    return relative


def _workspace_root_for(resolved_path: Path, method_key: str) -> Path:
    relative = _method_key_relative_path(method_key)
    root = resolve_workspace_root(resolved_path, relative)
    if root is None:
        raise ValueError("source_path_method_key_mismatch")
    return root


def _apply_work_root() -> Path:
    root = Path.cwd() / "build" / "remediation-apply-work"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _publish_workspace_revision(workspace_root: Path) -> WorkspacePublication:
    return ingest(workspace_root.as_posix(), progress_callback=None, source_roots=None)


def _build_search_embeddings() -> None:
    EmbeddingService.build_embeddings(progress_callback=None)


def _required_evidence_source_sha256(context: dict[str, Any]) -> str:
    evidence_raw = context.get("evidence")
    evidence: dict[str, Any] = evidence_raw if isinstance(evidence_raw, dict) else {}
    value = evidence.get("source_sha256")
    if not isinstance(value, str) or not value:
        raise ValueError("evidence.source_sha256 is required")
    return value


def _stale_verification(rule_id: str) -> dict[str, Any]:
    return {
        "status": "STALE_CANDIDATE",
        "policy_status": "NOT_EVALUATED",
        "build_status": "NOT_EVALUATED",
        "target_rule_status": "UNKNOWN",
        "rule_id": rule_id,
        "stale_reasons": ["source_sha256_mismatch"],
        "error": "source changed during remediation",
    }


def _prepare_and_snapshot_source(
    service: Any,
    file_path: str,
    method_key: str,
    context: dict[str, Any],
) -> tuple[Path, Path, bytes, str, Any] | tuple[str, str, str]:
    """Resolve file path, workspace root, expected hash, and baseline snapshot.

    Returns (resolved_path, workspace_root, original_bytes, expected_sha, snapshot)
    or (error_kind, status, error_message).
    """
    resolved_path = service._resolve_file_path(file_path)
    if resolved_path is None:
        return ("error", "VERIFICATION_ERROR", f"Could not resolve file path: {file_path}")
    try:
        workspace_root = _workspace_root_for(resolved_path, method_key)
    except ValueError as exc:
        return ("error", "INVALID", str(exc))
    try:
        expected_source_sha256 = _required_evidence_source_sha256(context)
    except ValueError as exc:
        return ("error", "VERIFICATION_ERROR", str(exc))
    original_bytes = resolved_path.read_bytes()
    try:
        from codegraph.ingestion.snapshots import SnapshotError, StaleSourceError, create_source_snapshot_from_bytes

        baseline_snapshot = create_source_snapshot_from_bytes(
            workspace_root=workspace_root,
            source_path=resolved_path,
            source_bytes=original_bytes,
            method_selector=method_key,
            expected_source_sha256=expected_source_sha256,
        )
        return (resolved_path, workspace_root, original_bytes, expected_source_sha256, baseline_snapshot)
    except StaleSourceError:
        return ("error", "VERIFICATION_ERROR", "stale_source_hash")
    except SnapshotError as exc:
        return ("error", "VERIFICATION_ERROR", str(exc))


def compile_verify_and_apply_candidate(
    *,
    service: Any,
    violation_id: str,
    method_key: str,
    context: dict[str, Any],
    resolved_path: Path,
    workspace_root: Path,
    source_relative_path: Path,
    original_bytes: bytes,
    expected_source_sha256: str,
    replacement: Any,
    mode: str,
    build_command: str | None,
    verify_candidate_fn: Any,
    ingest_fn: Any,
    rollback_fn: Any,
    build_embeddings_fn: Any,
    tempfile_mod: Any = None,
) -> tuple[CompilationResult, dict[str, Any], bool, bool]:
    import tempfile as _default_tempfile
    tf = tempfile_mod or _default_tempfile

    from codegraph.common.workspace_lock import workspace_mutation_guard

    compilation: CompilationResult = {
        "attempted": False,
        "success": False,
        "output_snippet": None,
        "skipped_reason": "No build system detected",
    }
    verification: dict[str, Any] = {}
    apply_successful = False
    live_workspace_modified = False
    restore_failed = False
    graph_rollback_failed = False
    cleanup: dict[str, bool | None] = {"file_restored": None, "revision_published": None}

    try:
        tempdir = tf.TemporaryDirectory(prefix="candidate-", dir=_apply_work_root())
        tmp = Path(tempdir.__enter__())
        try:
            _temp_root, temp_file_path, temp_build_root = service._prepare_temp_workspace(tmp, resolved_path)
            temp_file_path.parent.mkdir(parents=True, exist_ok=True)
            temp_file_path.write_bytes(replacement.candidate_file_bytes)
            compilation = service._compile_project(temp_build_root, build_command=build_command)

            verification_workspace = tmp / "verification-workspace"
            verification_source = verification_workspace / source_relative_path
            verification_source.parent.mkdir(parents=True, exist_ok=True)
            verification_source.write_bytes(original_bytes)
            candidate_method_rel = Path(".candidate") / "candidate-method.java"
            candidate_method_path = verification_workspace / candidate_method_rel
            candidate_method_path.parent.mkdir(parents=True, exist_ok=True)
            candidate_method_path.write_bytes(replacement.candidate_method_bytes)
            verification = verify_candidate_fn(
                workspace_root=verification_workspace,
                source=source_relative_path,
                method_selector=method_key,
                candidate=candidate_method_rel,
                rule_id=str(context.get("rule_id")),
                expected_source_sha256=expected_source_sha256,
                work_dir=tmp / "verify",
            )
        finally:
            tempdir.__exit__(None, None, None)

        apply_successful = _can_commit_apply(mode, verification, compilation)
        if apply_successful:
            with workspace_mutation_guard():
                if resolved_path.read_bytes() != original_bytes:
                    verification = _stale_verification(str(context.get("rule_id")))
                    apply_successful = False
                else:
                    publication = None
                    live_workspace_modified = True
                    resolved_path.write_bytes(replacement.candidate_file_bytes)
                    try:
                        publication = ingest_fn(workspace_root.as_posix(), progress_callback=None, source_roots=None)
                        cleanup["revision_published"] = True
                        build_embeddings_fn()
                    except Exception as publication_exc:
                        rollback_error = None
                        if publication is not None:
                            try:
                                rollback_fn(publication)
                            except Exception as exc:
                                rollback_error = exc
                                graph_rollback_failed = True
                        cleanup["file_restored"] = _restore_file(
                            resolved_path, original_bytes, replacement.candidate_file_bytes
                        )
                        live_workspace_modified = False
                        if rollback_error is not None:
                            raise RuntimeError(
                                f"{publication_exc}; graph rollback failed: {rollback_error}"
                            ) from publication_exc
                        raise
    except Exception as exc:
        _err = {"err": str(exc), "err_type": type(exc).__name__, "violation_id": violation_id}
        if LOGGER.isEnabledFor(logging.DEBUG):
            LOGGER.exception("Apply remediation failed", extra=_err)
        else:
            LOGGER.error("Apply remediation failed", extra=_err)
        apply_successful = False
        verification = {**verification, "error": str(exc)}
    finally:
        if live_workspace_modified and _should_restore(mode, apply_successful):
            cleanup["file_restored"] = _restore_file(resolved_path, original_bytes, replacement.candidate_file_bytes)
        restore_failed = graph_rollback_failed or any(restored is False for restored in cleanup.values())

    verification["cleanup"] = cleanup
    return compilation, verification, apply_successful, restore_failed
