from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from codegraph.evaluation.benchmark import extract_testcase_id
from codegraph.evaluation.calibration import (
    ATTEMPTED_REMEDIATION_STATUSES,
    FULLY_VERIFIED_LABEL_DEFINITION,
    _calibration_block,
    _collect_calibration_points,
    _safe_float,
    build_confidence_calibration,
    is_fully_verified,
    render_calibration_markdown,
)
from codegraph.evaluation.io import (
    render_latex_table,
    render_markdown_table,
    write_csv,
    write_json,
)

__all__ = [
    "ATTEMPTED_REMEDIATION_STATUSES",
    "FULLY_VERIFIED_LABEL_DEFINITION",
    "TRACKED_FINAL_STATUSES",
    "RemediationRuntime",
    "_calibration_block",
    "_collect_calibration_points",
    "_safe_float",
    "build_case_id",
    "build_confidence_calibration",
    "build_metrics_payload",
    "build_remediation_result",
    "build_skipped_result",
    "build_stage_counts",
    "is_fully_verified",
    "render_calibration_markdown",
    "render_summary_markdown",
    "tracked_status_counts",
    "untracked_status_counts",
    "utc_now_iso",
    "write_final_artifacts",
]

TRACKED_FINAL_STATUSES: Sequence[str] = (
    "OK",
    "NO_FIX",
    "GENERATION_ERROR",
    "REPLACEMENT_ERROR",
    "BUILD_ERROR",
    "VERIFICATION_ERROR",
)


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _safe_slug(value: str | None) -> str:
    normalized = re.sub(r"[^A-Za-z0-9_.-]+", "-", (value or "").strip())
    normalized = normalized.strip("-._")
    return normalized or "unknown"


def build_case_id(violation: Mapping[str, Any]) -> str:
    violation_id = str(violation.get("violation_id") or "unknown")
    target_method = str(violation.get("target_method") or "")
    file_path = str((violation.get("evidence") or {}).get("file_path") or violation.get("file_path") or "")
    testcase_id = extract_testcase_id(target_method or file_path) or "unknown"
    identity = "|".join((violation_id, target_method, file_path))
    digest = hashlib.sha1(identity.encode("utf-8")).hexdigest()[:10]
    return f"{_safe_slug(testcase_id)}_{_safe_slug(violation_id)}_{digest}"


def tracked_status_counts(results: Iterable[Mapping[str, Any]]) -> dict[str, int]:
    counts = {status: 0 for status in TRACKED_FINAL_STATUSES}
    for item in results:
        status = str(item.get("status") or "")
        if status in counts:
            counts[status] += 1
    return counts


def untracked_status_counts(results: Iterable[Mapping[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in results:
        status = str(item.get("status") or "")
        if not status or status in TRACKED_FINAL_STATUSES:
            continue
        counts[status] = counts.get(status, 0) + 1
    return counts


def build_stage_counts(results: Iterable[Mapping[str, Any]]) -> dict[str, int]:
    items = list(results)
    return {
        "attempted": len(items),
        "structured_valid": sum(1 for item in items if item.get("structured_valid") is True),
        "replacement_applied": sum(1 for item in items if item.get("replacement_applied") is True),
        "build_attempted": sum(1 for item in items if item.get("build_attempted") is True),
        "build_success": sum(1 for item in items if item.get("build_success") is True),
        "policy_fixed": sum(1 for item in items if item.get("policy_fixed") is True),
    }


def build_remediation_result(
    *,
    violation: Mapping[str, Any],
    apply_result: Mapping[str, Any],
    case_id: str,
) -> dict[str, Any]:
    verification = apply_result.get("verification") or {}
    compilation = apply_result.get("compilation") or {}
    generation = apply_result.get("generation")
    build_pass = compilation.get("success") if compilation.get("attempted") else None
    policy_fixed = apply_result.get("status") == "OK" and verification.get("target_rule_status") == "PASS"
    replacement_applied = bool(apply_result.get("updated_source_code"))
    structured_valid = isinstance(generation, dict) and generation.get("raw_response_valid") is True

    confidence = apply_result.get("confidence") or None
    confidence_score = _safe_float((confidence or {}).get("score")) if confidence else None
    confidence_band = (confidence or {}).get("band") if confidence else None
    fully_verified = policy_fixed and build_pass is True
    evidence = violation.get("evidence") or {}
    return {
        "case_id": case_id,
        "artifact_dir": f"cases/{case_id}",
        "violation_id": violation.get("violation_id"),
        "target_method": violation.get("target_method"),
        "file_path": evidence.get("file_path") or violation.get("file_path"),
        "status": apply_result.get("status"),
        "error": apply_result.get("error"),
        "patch_applied": replacement_applied,
        "policy_pass": policy_fixed,
        "build_pass": build_pass,
        "category": violation.get("category"),
        "verification": verification,
        "compilation": compilation,
        "diff": apply_result.get("diff"),
        "generation": generation,
        "errors": apply_result.get("errors"),
        "attempt_count": apply_result.get("attempt_count"),
        "raw_capture_files": apply_result.get("raw_capture_files"),
        "structured_valid": structured_valid,
        "replacement_applied": replacement_applied,
        "build_attempted": compilation.get("attempted") is True,
        "build_success": build_pass is True,
        "policy_fixed": policy_fixed,
        "fully_verified": fully_verified,
        "confidence": confidence,
        "confidence_score": confidence_score,
        "confidence_band": confidence_band,
    }


def build_skipped_result(
    *,
    violation: Mapping[str, Any],
    case_id: str,
    error: str,
) -> dict[str, Any]:
    evidence = violation.get("evidence") or {}
    return {
        "case_id": case_id,
        "artifact_dir": f"cases/{case_id}",
        "violation_id": violation.get("violation_id"),
        "target_method": violation.get("target_method"),
        "file_path": evidence.get("file_path") or violation.get("file_path"),
        "status": "SKIPPED",
        "error": error,
        "patch_applied": False,
        "policy_pass": False,
        "build_pass": None,
        "category": violation.get("category"),
        "verification": {},
        "compilation": {},
        "diff": None,
        "generation": None,
        "errors": [error],
        "attempt_count": 0,
        "raw_capture_files": [],
        "structured_valid": False,
        "replacement_applied": False,
        "build_attempted": False,
        "build_success": False,
        "policy_fixed": False,
        "fully_verified": False,
        "confidence": None,
        "confidence_score": None,
        "confidence_band": None,
    }


def build_metrics_payload(
    *,
    benchmark_root: Path,
    truth_path: Path,
    truth_schema: dict[str, Any],
    selection_cfg: dict[str, Any],
    coverage_by_category: dict[str, Any],
    mode: str,
    max_attempts: int,
    legacy_build_command_arg: str | None,
    results: Sequence[dict[str, Any]],
) -> dict[str, Any]:
    stage_counts = build_stage_counts(results)
    status_counts = tracked_status_counts(results)
    fix_rate = stage_counts["policy_fixed"] / stage_counts["attempted"] if stage_counts["attempted"] else 0.0
    build_rate = (
        stage_counts["build_success"] / stage_counts["build_attempted"] if stage_counts["build_attempted"] else 0.0
    )
    return {
        "generated_at": utc_now_iso(),
        "benchmark_root": benchmark_root.as_posix(),
        "ground_truth_file": truth_path.as_posix(),
        "ground_truth_schema": truth_schema,
        "selection": selection_cfg,
        "coverage_by_category": coverage_by_category,
        "mode": mode,
        "max_attempts": max_attempts,
        "attempted": stage_counts["attempted"],
        "fix_success": stage_counts["policy_fixed"],
        "structured_valid": stage_counts["structured_valid"],
        "replacement_applied": stage_counts["replacement_applied"],
        "policy_pass_count": stage_counts["policy_fixed"],
        "build_attempted": stage_counts["build_attempted"],
        "build_success": stage_counts["build_success"],
        "fix_success_rate": round(fix_rate, 4),
        "build_success_rate": round(build_rate, 4),
        "confidence_calibration": build_confidence_calibration(results),
        "legacy_build_command_arg": legacy_build_command_arg,
        "final_status_counts": status_counts,
        "untracked_status_counts": untracked_status_counts(results),
        "results_jsonl": "results.jsonl",
        "cases_dir": "cases",
        "results": list(results),
    }


def render_summary_markdown(
    *,
    stage_counts: Mapping[str, int],
    status_counts: Mapping[str, int],
    build_success_rate: float,
    fix_success_rate: float,
    runtime_status: str,
    total_cases: int | None = None,
    recent_results: Sequence[Mapping[str, Any]] | None = None,
    untracked_counts: Mapping[str, int] | None = None,
    calibration: Mapping[str, Any] | None = None,
) -> str:
    attempted = stage_counts.get("attempted", 0)
    total_display = f"`{attempted}`" if total_cases is None else f"`{attempted}` / `{total_cases}`"

    lines = [
        "# Remediation Summary",
        "",
        f"- Status: `{runtime_status}`",
        f"- Attempted: {total_display}",
        f"- Structured valid: `{stage_counts.get('structured_valid', 0)}`",
        f"- Replacement applied: `{stage_counts.get('replacement_applied', 0)}`",
        f"- Policy fixed: `{stage_counts.get('policy_fixed', 0)}`",
        f"- Build attempted: `{stage_counts.get('build_attempted', 0)}`",
        f"- Build success: `{stage_counts.get('build_success', 0)}`",
        f"- Fully verified success rate: `{round(fix_success_rate, 4)}`",
        f"- Build success rate: `{round(build_success_rate, 4)}`",
        "",
        "## Final Status Counts",
    ]
    for status in TRACKED_FINAL_STATUSES:
        lines.append(f"- `{status}`: `{status_counts.get(status, 0)}`")

    extra_counts = dict(untracked_counts or {})
    if extra_counts:
        lines.extend(["", "## Other Status Counts"])
        for status, count in sorted(extra_counts.items()):
            lines.append(f"- `{status}`: `{count}`")

    if recent_results:
        lines.extend(["", "## Recent Cases"])
        for item in recent_results:
            case_id = item.get("case_id") or "unknown"
            status = item.get("status") or "unknown"
            violation_id = item.get("violation_id") or "unknown"
            lines.append(f"- `{case_id}`: `{status}` ({violation_id})")

    if calibration is not None:
        lines.extend(
            [
                "",
                "## Confidence Calibration",
                f"- `Brier`: `{calibration.get('brier_score', 'n/a')}`",
                f"- `ECE`: `{calibration.get('ece', 'n/a')}`",
                "- Full reliability bins are in `remediation_calibration.json`.",
            ]
        )

    lines.extend(
        [
            "",
            "Interpretation:",
            ("- `Policy fixed` means the target rule was removed and no new violations were introduced."),
            "- `Build success` means compilation was attempted and passed.",
            "- `Fully verified` is the current remediation benchmark success metric.",
        ]
    )
    return "\n".join(lines)


def write_final_artifacts(
    output_dir: Path,
    metrics: Mapping[str, Any],
    *,
    table_format: str,
) -> None:
    write_json(output_dir / "remediation_metrics.json", metrics)
    calibration = metrics.get("confidence_calibration")
    if calibration is not None:
        write_json(output_dir / "confidence_calibration.json", calibration)
        write_json(output_dir / "remediation_calibration.json", calibration)
        (output_dir / "remediation_calibration.md").write_text(
            render_calibration_markdown(calibration),
            encoding="utf-8",
        )
    results = metrics.get("results") or []
    write_csv(
        output_dir / "remediation_metrics.csv",
        [
            {
                "violation_id": item.get("violation_id"),
                "target_method": item.get("target_method"),
                "status": item.get("status"),
                "patch_applied": item.get("patch_applied"),
                "policy_pass": item.get("policy_pass"),
                "build_pass": item.get("build_pass"),
                "fully_verified": item.get("fully_verified"),
                "confidence_score": item.get("confidence_score"),
                "confidence_band": item.get("confidence_band"),
                "category": item.get("category"),
                "error": item.get("error"),
            }
            for item in results
        ],
        fieldnames=[
            "violation_id",
            "target_method",
            "status",
            "patch_applied",
            "policy_pass",
            "build_pass",
            "fully_verified",
            "confidence_score",
            "confidence_band",
            "category",
            "error",
        ],
    )

    headers = ["Metric", "Value"]
    table_rows = [
        ["Fix Success Rate", metrics.get("fix_success_rate", 0.0)],
        ["Build Success Rate", metrics.get("build_success_rate", 0.0)],
        ["Structured Valid", metrics.get("structured_valid", 0)],
        ["Replacement Applied", metrics.get("replacement_applied", 0)],
        ["Policy Pass Count", metrics.get("policy_pass_count", 0)],
        ["Build Attempts", metrics.get("build_attempted", 0)],
        ["Attempted", metrics.get("attempted", 0)],
    ]
    if calibration is not None:
        table_rows.append(["Confidence Brier", calibration.get("brier_score", "n/a")])
        table_rows.append(["Confidence ECE", calibration.get("ece", "n/a")])
    if table_format == "tex":
        table = render_latex_table(
            headers,
            table_rows,
            caption="Remediation Success Metrics",
        )
        (output_dir / "table.tex").write_text(table, encoding="utf-8")
    else:
        table = render_markdown_table(headers, table_rows)
        (output_dir / "table.md").write_text(table, encoding="utf-8")

    summary = render_summary_markdown(
        stage_counts=build_stage_counts(results),
        status_counts=metrics.get("final_status_counts") or {},
        build_success_rate=float(metrics.get("build_success_rate") or 0.0),
        fix_success_rate=float(metrics.get("fix_success_rate") or 0.0),
        runtime_status="completed",
        total_cases=metrics.get("attempted"),
        recent_results=list(results)[-5:],
        untracked_counts=metrics.get("untracked_status_counts") or {},
        calibration=calibration if isinstance(calibration, Mapping) else None,
    )
    (output_dir / "summary.md").write_text(summary, encoding="utf-8")


@dataclass
class RemediationRuntime:
    output_dir: Path
    benchmark_root: Path
    truth_path: Path
    truth_schema: dict[str, Any]
    selection_cfg: dict[str, Any]
    coverage_by_category: dict[str, Any]
    mode: str
    max_attempts: int

    def __post_init__(self) -> None:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.cases_dir = self.output_dir / "cases"
        self.cases_dir.mkdir(parents=True, exist_ok=True)
        self.progress_path = self.output_dir / "progress.json"
        self.summary_path = self.output_dir / "summary.md"
        self.results_jsonl_path = self.output_dir / "results.jsonl"
        self.started_at = datetime.now(UTC)
        self.total_cases = 0
        self.completed_results: list[dict[str, Any]] = []
        self.results_handle = self.results_jsonl_path.open("w", encoding="utf-8")

    def close(self) -> None:
        if not self.results_handle.closed:
            self.results_handle.close()

    def elapsed_seconds(self) -> float:
        return (datetime.now(UTC) - self.started_at).total_seconds()

    def write_stage_progress(self, stage: str, message: str, **extra: Any) -> None:
        payload = {
            "status": "running",
            "stage": stage,
            "message": message,
            "started_at": self.started_at.isoformat(),
            "updated_at": utc_now_iso(),
            "elapsed_seconds": round(self.elapsed_seconds(), 2),
            "processed_cases": len(self.completed_results),
            "total_cases": self.total_cases or None,
            "percent_complete": None,
            "eta_seconds": None,
            "attempted": len(self.completed_results),
            "structured_valid": 0,
            "replacement_applied": 0,
            "build_attempted": 0,
            "build_success": 0,
            "policy_fixed": 0,
            "final_status_counts": {status: 0 for status in TRACKED_FINAL_STATUSES},
            "mode": self.mode,
            "max_attempts": self.max_attempts,
            **extra,
        }
        write_json(self.progress_path, payload)

    def case_dir(self, case_id: str) -> Path:
        return self.cases_dir / case_id

    def prepare_case(self, violation: Mapping[str, Any]) -> tuple[str, Path]:
        case_id = build_case_id(violation)
        case_dir = self.case_dir(case_id)
        case_dir.mkdir(parents=True, exist_ok=True)
        write_json(case_dir / "violation.json", dict(violation))
        return case_id, case_dir

    def begin(self, total_cases: int) -> None:
        self.total_cases = total_cases
        self.write_live_artifacts(status="running", stage="remediation")

    def record_case(
        self,
        *,
        apply_result: Mapping[str, Any],
        result: dict[str, Any],
    ) -> None:
        case_dir = self.case_dir(str(result["case_id"]))
        case_dir.mkdir(parents=True, exist_ok=True)
        write_json(case_dir / "result.json", result)
        write_json(case_dir / "apply_result.json", dict(apply_result))

        diff = apply_result.get("diff")
        if isinstance(diff, str) and diff:
            (case_dir / "diff.patch").write_text(diff, encoding="utf-8")

        verification = apply_result.get("verification")
        if isinstance(verification, dict) and verification:
            write_json(case_dir / "verification.json", verification)

        compilation = apply_result.get("compilation")
        if isinstance(compilation, dict) and compilation:
            write_json(case_dir / "compilation.json", compilation)

        generation = apply_result.get("generation")
        if isinstance(generation, dict) and generation:
            write_json(case_dir / "generation.json", generation)

        self.completed_results.append(result)
        self.results_handle.write(json.dumps(result) + "\n")
        self.results_handle.flush()

        self.write_live_artifacts(
            status="running",
            stage="remediation",
            latest_case={
                "case_id": result.get("case_id"),
                "violation_id": result.get("violation_id"),
                "target_method": result.get("target_method"),
                "file_path": result.get("file_path"),
                "status": result.get("status"),
                "category": result.get("category"),
                "artifact_dir": result.get("artifact_dir"),
            },
        )

    def finalize(self, *, status: str) -> None:
        self.write_live_artifacts(status=status, stage="finalization")
        self.close()

    def write_live_artifacts(
        self,
        *,
        status: str,
        stage: str,
        latest_case: dict[str, Any] | None = None,
    ) -> None:
        stage_counts = build_stage_counts(self.completed_results)
        status_counts = tracked_status_counts(self.completed_results)
        untracked_counts = untracked_status_counts(self.completed_results)
        elapsed = self.elapsed_seconds()
        if stage_counts["attempted"] > 0 and self.total_cases > stage_counts["attempted"]:
            seconds_per_item = elapsed / stage_counts["attempted"]
            eta_seconds = round(
                seconds_per_item * (self.total_cases - stage_counts["attempted"]),
                2,
            )
        else:
            eta_seconds = 0.0
        percent_complete = (stage_counts["attempted"] / self.total_cases) if self.total_cases else 1.0
        fix_success_rate = (
            stage_counts["policy_fixed"] / stage_counts["attempted"] if stage_counts["attempted"] else 0.0
        )
        build_success_rate = (
            stage_counts["build_success"] / stage_counts["build_attempted"] if stage_counts["build_attempted"] else 0.0
        )
        progress_payload = {
            "status": status,
            "stage": stage,
            "started_at": self.started_at.isoformat(),
            "updated_at": utc_now_iso(),
            "elapsed_seconds": round(elapsed, 2),
            "processed_cases": stage_counts["attempted"],
            "total_cases": self.total_cases,
            "percent_complete": round(percent_complete, 4),
            "eta_seconds": eta_seconds,
            "attempted": stage_counts["attempted"],
            "structured_valid": stage_counts["structured_valid"],
            "replacement_applied": stage_counts["replacement_applied"],
            "build_attempted": stage_counts["build_attempted"],
            "build_success": stage_counts["build_success"],
            "policy_fixed": stage_counts["policy_fixed"],
            "final_status_counts": status_counts,
            "untracked_status_counts": untracked_counts,
            "mode": self.mode,
            "max_attempts": self.max_attempts,
            "latest_case": latest_case,
        }
        write_json(self.progress_path, progress_payload)

        summary = render_summary_markdown(
            stage_counts=stage_counts,
            status_counts=status_counts,
            build_success_rate=build_success_rate,
            fix_success_rate=fix_success_rate,
            runtime_status=status,
            total_cases=self.total_cases,
            recent_results=self.completed_results[-5:],
            untracked_counts=untracked_counts,
            calibration=build_confidence_calibration(self.completed_results, bins=10),
        )
        self.summary_path.write_text(summary, encoding="utf-8")
