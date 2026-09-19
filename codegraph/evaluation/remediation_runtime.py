from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

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
from codegraph.evaluation.io import write_json
from codegraph.evaluation.remediation_runtime_helpers import (
    TRACKED_FINAL_STATUSES,
    build_agentic_outcome_summary,
    build_agentic_remediation_result,
    build_case_id,
    build_remediation_result,
    build_skipped_result,
    build_stage_counts,
    tracked_status_counts,
    untracked_status_counts,
    utc_now_iso,
)
from codegraph.evaluation.remediation_runtime_writers import (
    build_metrics_payload,
    render_summary_markdown,
    write_final_artifacts,
)

__all__ = [
    "ATTEMPTED_REMEDIATION_STATUSES",
    "FULLY_VERIFIED_LABEL_DEFINITION",
    "TRACKED_FINAL_STATUSES",
    "RemediationRuntime",
    "_calibration_block",
    "_collect_calibration_points",
    "_safe_float",
    "build_agentic_outcome_summary",
    "build_agentic_remediation_result",
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
