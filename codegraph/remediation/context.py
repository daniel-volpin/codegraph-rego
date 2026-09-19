from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any

from codegraph.ingestion.snapshots import (
    SnapshotError,
    StaleSourceError,
    create_source_snapshot_from_bytes,
)
from codegraph.remediation.method_key_paths import parse_method_key_relative_path, resolve_workspace_root
from codegraph.remediation.virtual_graph_builder import (
    build_virtual_graph_context,
    dedupe_fields,
    sanitize_method_snippet,
)

__all__ = [
    "ContextSourceRefusalError",
    "build_virtual_graph_context",
    "cached_policy_evaluation",
    "clear_policy_evaluation_cache",
    "dedupe_fields",
    "format_numbered_lines",
    "gather_violation_context",
    "sanitize_method_snippet",
]

LOGGER = logging.getLogger(__name__)
_POLICY_CACHE: dict[str, dict[str, Any]] = {}
_CACHE_TTL_SECONDS = 30.0


class ContextSourceRefusalError(ValueError):
    def __init__(
        self,
        reason: str,
        *,
        method_key: str | None = None,
        file_path: str | None = None,
        status: str = "STALE_SOURCE",
    ) -> None:
        super().__init__(reason)
        self.reason = reason
        self.method_key = method_key
        self.file_path = file_path
        self.status = status


def format_numbered_lines(lines: list[str]) -> str:
    return "\n".join(f"{idx + 1}: {line}" for idx, line in enumerate(lines))


def clear_policy_evaluation_cache() -> None:
    _POLICY_CACHE.clear()


def cached_policy_evaluation(evaluate_policies_fn, *, cache_key: str | None = None) -> dict[str, Any]:
    now = time.monotonic()
    key = str(cache_key or "default")
    cached = _POLICY_CACHE.get(key)
    if cached and now - float(cached.get("timestamp", 0.0)) < _CACHE_TTL_SECONDS:
        return cached.get("data") or {}
    data = evaluate_policies_fn()
    _POLICY_CACHE[key] = {
        "timestamp": now,
        "data": data,
    }
    return data


def _violation_rule_id(violation: dict[str, Any]) -> str | None:
    value = violation.get("violation_id") or violation.get("id")
    return str(value) if value else None


def _violation_method(violation: dict[str, Any]) -> str | None:
    value = violation.get("target_method") or violation.get("method")
    return str(value) if value else None


def _violation_matches(
    violation: dict[str, Any],
    *,
    violation_id: str,
    method_key: str | None,
    file_path: str | None,
) -> bool:
    current_id = _violation_rule_id(violation)
    if current_id != str(violation_id):
        return False

    current_method_key = violation.get("method_key")
    if not method_key or not current_method_key or method_key != current_method_key:
        return False

    path = violation.get("file_path")
    return not (file_path and path and file_path != path)


def _evaluate_baseline_violations(
    policy_evaluator_cls,
    method_key: str | None,
    logger: logging.Logger,
) -> list[dict[str, Any]] | None:
    if not method_key:
        return None
    evaluator = policy_evaluator_cls()
    evaluation = evaluator.evaluate(method_key)
    if evaluation.get("error"):
        logger.warning("Baseline evaluation failed for %s: %s", method_key, evaluation.get("error"))
        raise ContextSourceRefusalError(
            f"baseline_evaluation_error: {evaluation.get('error')}",
            method_key=method_key,
            status="VERIFICATION_ERROR",
        )
    return evaluation.get("violations") or []


def _extract_exact_method_source(
    violation: dict[str, Any],
    *,
    method_key: str,
    resolve_file_path_fn,
    logger: logging.Logger,
) -> tuple[str, str, bytes, str, str, Any]:
    evidence = violation.get("evidence") or {}
    expected_source_sha256 = evidence.get("source_sha256")
    resolved_path = resolve_file_path_fn(violation.get("file_path") or "")
    if not expected_source_sha256:
        raise ContextSourceRefusalError(
            "missing_source_sha256",
            method_key=method_key,
            file_path=violation.get("file_path"),
        )
    if resolved_path is None:
        raise ContextSourceRefusalError(
            "source_file_not_found",
            method_key=method_key,
            file_path=violation.get("file_path"),
        )
    try:
        source_bytes = Path(resolved_path).read_bytes()
        snapshot = create_source_snapshot_from_bytes(
            workspace_root=_workspace_root_for_method_key(Path(resolved_path), method_key),
            source_path=resolved_path,
            source_bytes=source_bytes,
            method_selector=method_key,
            expected_source_sha256=str(expected_source_sha256),
        )
        return (
            snapshot.method_source,
            format_numbered_lines(snapshot.method_source.splitlines()),
            source_bytes,
            snapshot.file_sha256,
            str(expected_source_sha256),
            snapshot,
        )
    except StaleSourceError as exc:
        raise ContextSourceRefusalError(
            "source_sha256_mismatch",
            method_key=method_key,
            file_path=violation.get("file_path"),
        ) from exc
    except SnapshotError as exc:
        raise ContextSourceRefusalError(
            str(exc),
            method_key=method_key,
            file_path=violation.get("file_path"),
        ) from exc
    except ContextSourceRefusalError:
        raise
    except Exception as exc:
        logger.debug("Failed to extract exact method span for %s: %s", method_key, exc)
        raise ContextSourceRefusalError(
            "source_snapshot_error",
            method_key=method_key,
            file_path=violation.get("file_path"),
        ) from exc


def _method_key_relative_path(method_key: str) -> Path:
    relative = parse_method_key_relative_path(method_key)
    if relative is None:
        raise ContextSourceRefusalError("invalid_method_key", method_key=method_key)
    return relative


def _workspace_root_for_method_key(resolved_path: Path, method_key: str) -> Path:
    relative = _method_key_relative_path(method_key)
    resolved = resolved_path.resolve()
    root = resolve_workspace_root(resolved, relative)
    if root is None:
        raise ContextSourceRefusalError(
            "method_key_source_path_mismatch", method_key=method_key, file_path=resolved.as_posix()
        )
    return root


def _context_payload(
    violation: dict[str, Any],
    *,
    rule_id: str,
    method: str | None,
    catalog_entry: Any,
    baseline_violations: list[dict[str, Any]] | None,
    exact_method_source: str | None,
    numbered_method_source: str | None,
    source_bytes: bytes | None,
    source_sha256: str | None,
    expected_source_sha256: str | None,
    build_remediation_plan_fn,
    source_snapshot: Any = None,
) -> dict[str, Any]:
    evidence = violation.get("evidence") or {}
    return {
        "violation": violation,
        "method_key": violation.get("method_key"),
        "target_method": method,
        "file_path": violation.get("file_path"),
        "rule_id": rule_id,
        "evidence": evidence,
        "catalog_entry": catalog_entry,
        "baseline_violations": baseline_violations,
        "exact_method_source": exact_method_source,
        "numbered_method_source": numbered_method_source,
        "source_bytes": source_bytes,
        "source_sha256": source_sha256,
        "expected_source_sha256": expected_source_sha256,
        "source_snapshot": source_snapshot,
        "remediation_plan": build_remediation_plan_fn(exact_method_source),
    }


def gather_violation_context(
    violation_id: str,
    *,
    method_key: str | None = None,
    file_path: str | None = None,
    policy_cache_key: str | None = None,
    evaluate_policies_fn,
    load_policy_catalog_fn,
    policy_evaluator_cls,
    resolve_file_path_fn,
    build_remediation_plan_fn,
    logger: logging.Logger = LOGGER,
) -> dict[str, Any] | None:
    if not method_key:
        return None
    result = cached_policy_evaluation(evaluate_policies_fn, cache_key=policy_cache_key)
    if result.get("error"):
        logger.error("Policy evaluation failed while gathering context: %s", result["error"])
        return None
    violations = result.get("violations") or []
    catalog = load_policy_catalog_fn()
    for violation in violations:
        if not isinstance(violation, dict):
            continue
        if not _violation_matches(
            violation,
            violation_id=violation_id,
            method_key=method_key,
            file_path=file_path,
        ):
            continue

        rule_id = _violation_rule_id(violation)
        if rule_id is None:
            continue
        method = _violation_method(violation)
        (
            exact_method_source,
            numbered_method_source,
            source_bytes,
            source_sha256,
            expected_source_sha256,
            source_snapshot,
        ) = _extract_exact_method_source(
            violation,
            method_key=method_key,
            resolve_file_path_fn=resolve_file_path_fn,
            logger=logger,
        )
        return _context_payload(
            violation,
            rule_id=rule_id,
            method=method,
            catalog_entry=catalog.get(rule_id) if isinstance(catalog, dict) else None,
            baseline_violations=_evaluate_baseline_violations(policy_evaluator_cls, method_key, logger),
            exact_method_source=exact_method_source,
            numbered_method_source=numbered_method_source,
            source_bytes=source_bytes,
            source_sha256=source_sha256,
            expected_source_sha256=expected_source_sha256,
            source_snapshot=source_snapshot,
            build_remediation_plan_fn=build_remediation_plan_fn,
        )
    return None
