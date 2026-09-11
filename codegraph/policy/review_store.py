from __future__ import annotations

import json
import subprocess
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

MAX_RECORD_BYTES = 200_000
MAX_STRING_CHARS = 20_000
MAX_NOTES_CHARS = 4_000
MAX_SOURCE_CODE_CHARS = 30_000
MAX_LIST_ITEMS = 200
MAX_DICT_KEYS = 500


@dataclass(frozen=True)
class AppendResult:
    status: str
    review_id: str | None = None
    store_path: str | None = None
    scrub_warnings: list[str] | None = None
    error: str | None = None


def _repo_root() -> Path:
    # /.../codegraph/policy/review_store.py -> policy -> codegraph -> repo root
    return Path(__file__).resolve().parents[2]


def _outputs_root(repo_root: Path) -> Path:
    return (repo_root / "outputs").resolve()


def resolve_review_store_path(store_path: str) -> tuple[Path | None, str | None]:
    repo_root = _repo_root()
    outputs_root = _outputs_root(repo_root)

    raw = (store_path or "").strip()
    if not raw:
        return None, "empty_store_path"

    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = repo_root / candidate
    resolved = candidate.resolve()

    # Hard safety: only allow writing under <repo>/outputs
    try:
        resolved.relative_to(outputs_root)
    except ValueError:
        return None, f"unsafe_store_path_outside_outputs:{resolved}"

    return resolved, None


def derive_violation_key(violation: dict[str, Any]) -> str:
    violation_id = violation.get("violation_id") or violation.get("id") or "unknown"
    target_method = violation.get("target_method") or violation.get("method") or ""
    file_path = violation.get("file_path") or ""
    return f"{violation_id}::{target_method}::{file_path}"


def _safe_len(value: Any) -> int | None:
    return len(value) if isinstance(value, list) else None


def _summarize_verification(verification: Any) -> dict[str, Any]:
    if not isinstance(verification, dict):
        return {}
    baseline = verification.get("baseline")
    after = verification.get("after")
    new_violations = verification.get("new_violations")
    remaining = verification.get("remaining_violations")
    return {
        "overall_status": verification.get("overall_status"),
        "target_rule_status": verification.get("target_rule_status"),
        "baseline_count": _safe_len(baseline),
        "after_count": _safe_len(after),
        "new_count": _safe_len(new_violations),
        "remaining_count": _safe_len(remaining),
    }


def _summarize_compilation(compilation: Any) -> dict[str, Any]:
    if not isinstance(compilation, dict):
        return {}
    return {
        "attempted": compilation.get("attempted"),
        "success": compilation.get("success"),
        "skipped_reason": compilation.get("skipped_reason"),
    }


def summarize_remediation_payload(payload: Any, *, kind: str) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    summary: dict[str, Any] = {
        "status": payload.get("status"),
        "rule_id": payload.get("rule_id"),
        "opa_status": payload.get("opa_status"),
        "error": payload.get("error"),
    }
    summary.update(_summarize_verification(payload.get("verification")))
    if kind == "apply":
        compilation = _summarize_compilation(payload.get("compilation"))
        if compilation:
            summary["compilation"] = compilation
    return summary


def _string_cap_for_path(path: str) -> int:
    if path.endswith(".notes"):
        return MAX_NOTES_CHARS
    if path.endswith(".violation.evidence.source_code"):
        return MAX_SOURCE_CODE_CHARS
    return MAX_STRING_CHARS


def scrub_value(value: Any, *, path: str) -> tuple[Any, list[str]]:
    warnings: list[str] = []

    if isinstance(value, str):
        cap = _string_cap_for_path(path)
        if len(value) > cap:
            warnings.append(f"truncated_string:{path}")
            return value[:cap], warnings
        return value, warnings

    if isinstance(value, list):
        if len(value) > MAX_LIST_ITEMS:
            warnings.append(f"truncated_list:{path}")
            value = value[:MAX_LIST_ITEMS]
        out: list[Any] = []
        for idx, item in enumerate(value):
            scrubbed, child_warnings = scrub_value(item, path=f"{path}[{idx}]")
            out.append(scrubbed)
            warnings.extend(child_warnings)
        return out, warnings

    if isinstance(value, dict):
        keys = sorted(value.keys(), key=lambda x: str(x))
        if len(keys) > MAX_DICT_KEYS:
            warnings.append(f"truncated_dict:{path}")
            keys = keys[:MAX_DICT_KEYS]
        out: dict[str, Any] = {}
        for key in keys:
            k = str(key)
            scrubbed, child_warnings = scrub_value(value.get(key), path=f"{path}.{k}")
            out[k] = scrubbed
            warnings.extend(child_warnings)
        return out, warnings

    return value, warnings


def _json_size_bytes(obj: Any) -> int:
    payload = json.dumps(obj, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return len(payload.encode("utf-8"))


def _drop_ladder(record: dict[str, Any], warnings: list[str]) -> tuple[dict[str, Any] | None, list[str]]:
    def current_size() -> int:
        return _json_size_bytes(record)

    def pop_path() -> Any:
        return record.get("violation") if isinstance(record.get("violation"), dict) else None

    if current_size() <= MAX_RECORD_BYTES:
        return record, warnings

    violation = pop_path()
    if isinstance(violation, dict):
        evidence = violation.get("evidence") if isinstance(violation.get("evidence"), dict) else None
        if isinstance(evidence, dict) and "vector_context" in evidence:
            evidence.pop("vector_context", None)
            warnings.append("drop_ladder:dropped_violation.evidence.vector_context")
            if current_size() <= MAX_RECORD_BYTES:
                return record, warnings

        gc = (
            evidence.get("graph_context")
            if isinstance(evidence, dict) and isinstance(evidence.get("graph_context"), dict)
            else None
        )
        if isinstance(gc, dict):
            for k in ("calls", "callers", "uses_fields"):
                if k in gc:
                    gc.pop(k, None)
            warnings.append("drop_ladder:reduced_violation.evidence.graph_context")
            if current_size() <= MAX_RECORD_BYTES:
                return record, warnings

        if isinstance(evidence, dict) and "source_code" in evidence:
            evidence.pop("source_code", None)
            warnings.append("drop_ladder:dropped_violation.evidence.source_code")
            if current_size() <= MAX_RECORD_BYTES:
                return record, warnings

        if "evidence" in violation:
            violation.pop("evidence", None)
            warnings.append("drop_ladder:dropped_violation.evidence")
            if current_size() <= MAX_RECORD_BYTES:
                return record, warnings

    llm = record.get("llm")
    if isinstance(llm, dict) and isinstance(llm.get("explanation"), str):
        if len(llm["explanation"]) > 5000:
            llm["explanation"] = llm["explanation"][:5000]
            warnings.append("drop_ladder:truncated_llm.explanation_5000")
            if current_size() <= MAX_RECORD_BYTES:
                return record, warnings

    remediation = record.get("remediation")
    if isinstance(remediation, dict) and "preview" in remediation:
        remediation.pop("preview", None)
        warnings.append("drop_ladder:dropped_remediation.preview")
        if current_size() <= MAX_RECORD_BYTES:
            return record, warnings
    if isinstance(remediation, dict) and "apply" in remediation:
        remediation.pop("apply", None)
        warnings.append("drop_ladder:dropped_remediation.apply")
        if current_size() <= MAX_RECORD_BYTES:
            return record, warnings

    if current_size() > MAX_RECORD_BYTES:
        return None, warnings
    return record, warnings


def _get_git_context(repo_root: Path) -> dict[str, str]:
    context: dict[str, str] = {}
    try:
        sha = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root.as_posix(),
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        if sha:
            context["git_sha"] = sha
    except Exception:
        pass
    try:
        branch = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=repo_root.as_posix(),
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        if branch:
            context["branch"] = branch
    except Exception:
        pass
    return context


def append_review_jsonl(
    *,
    store_path: str,
    label: str,
    notes: str | None,
    violation: dict[str, Any],
    explanation: str | None,
    llm_model: str | None,
    include_graph_context: bool,
    remediation_preview: dict[str, Any] | None = None,
    remediation_apply: dict[str, Any] | None = None,
) -> AppendResult:
    resolved, error = resolve_review_store_path(store_path)
    if error:
        return AppendResult(status="ERROR", error=error, scrub_warnings=[])

    assert resolved is not None  # for mypy
    resolved.parent.mkdir(parents=True, exist_ok=True)

    review_id = str(uuid.uuid4())
    created_at = datetime.now(UTC).isoformat()
    repo_root = _repo_root()

    remediation: dict[str, Any] = {}
    if remediation_preview:
        remediation["preview"] = summarize_remediation_payload(remediation_preview, kind="preview")
    if remediation_apply:
        remediation["apply"] = summarize_remediation_payload(remediation_apply, kind="apply")

    record: dict[str, Any] = {
        "review_id": review_id,
        "created_at": created_at,
        "violation_key": derive_violation_key(violation),
        "label": label,
        "notes": notes,
        "violation": violation,
        "llm": {
            "model": llm_model,
            "include_graph_context": include_graph_context,
            "explanation": explanation,
        },
        "remediation": remediation,
        "context": _get_git_context(repo_root),
    }

    scrubbed, warnings = scrub_value(record, path="$")
    if not isinstance(scrubbed, dict):
        return AppendResult(status="ERROR", error="scrub_failed", scrub_warnings=warnings)

    scrubbed2, warnings = _drop_ladder(scrubbed, warnings)
    if scrubbed2 is None:
        return AppendResult(
            status="ERROR",
            error="record_too_large_after_scrub",
            scrub_warnings=warnings,
        )

    if _json_size_bytes(scrubbed2) > MAX_RECORD_BYTES:
        return AppendResult(
            status="ERROR",
            error="record_too_large_after_drop_ladder",
            scrub_warnings=warnings,
        )

    try:
        line = json.dumps(scrubbed2, ensure_ascii=True, sort_keys=True)
        with open(resolved.as_posix(), "a", encoding="utf-8") as handle:
            handle.write(line)
            handle.write("\n")
    except Exception as exc:
        return AppendResult(
            status="ERROR",
            error=f"write_failed:{exc}",
            scrub_warnings=warnings,
        )

    return AppendResult(
        status="OK",
        review_id=review_id,
        store_path=resolved.as_posix(),
        scrub_warnings=warnings,
    )
