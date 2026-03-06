from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from codegraph.evaluation.io import write_json


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ExplanationRuntime:
    output_dir: Path
    benchmark_root: Path
    truth_path: Path
    truth_schema: Dict[str, Any]
    selection_cfg: Dict[str, Any]
    coverage_by_category: Dict[str, Any]
    sample_per_category: int

    def __post_init__(self) -> None:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.progress_path = self.output_dir / "progress.json"
        self.partial_metrics_path = self.output_dir / "partial_metrics.json"
        self.samples_path = self.output_dir / "explanation_samples.jsonl"
        self.started_at = datetime.now(timezone.utc)

        self.total_target_violations = 0
        self.total_count = 0
        self.total_with = 0
        self.total_without = 0
        self.sample_count = 0

        self.current_category_id: Optional[str] = None
        self.current_category_label: Optional[str] = None
        self.current_category_done = 0
        self.current_category_total = 0

        self.samples_handle = self.samples_path.open("w", encoding="utf-8") if self.sample_per_category > 0 else None

    def elapsed_seconds(self) -> float:
        return (datetime.now(timezone.utc) - self.started_at).total_seconds()

    def write_stage_progress(self, stage: str, message: str, **extra: Any) -> None:
        payload = {
            "status": "running",
            "stage": stage,
            "message": message,
            "started_at": self.started_at.isoformat(),
            "updated_at": utc_now_iso(),
            "elapsed_seconds": round(self.elapsed_seconds(), 2),
            "processed_violations": None,
            "total_violations": None,
            "percent_complete": None,
            "eta_seconds": None,
            **extra,
        }
        write_json(self.progress_path, payload)

    def begin_explanations(self, total_target_violations: int, metrics: Dict[str, Any]) -> None:
        self.total_target_violations = total_target_violations
        self.write_live_artifacts(status="running", stage="explanation", metrics=metrics)

    def start_category(self, category_id: str, category_label: str, category_total: int, metrics: Dict[str, Any]) -> None:
        self.current_category_id = category_id
        self.current_category_label = category_label
        self.current_category_done = 0
        self.current_category_total = category_total
        self.write_live_artifacts(status="running", stage="explanation", metrics=metrics)

    def record_violation_result(self, with_context_hit: bool, without_context_hit: bool, metrics: Dict[str, Any]) -> None:
        self.total_count += 1
        self.current_category_done += 1
        if with_context_hit:
            self.total_with += 1
        if without_context_hit:
            self.total_without += 1
        self.write_live_artifacts(status="running", stage="explanation", metrics=metrics)

    def write_sample(self, sample: Dict[str, Any]) -> None:
        if self.samples_handle is None:
            return
        self.samples_handle.write(json.dumps(sample) + "\n")
        self.samples_handle.flush()
        self.sample_count += 1

    def close(self) -> None:
        if self.samples_handle is not None:
            self.samples_handle.close()
            self.samples_handle = None

    def finalize(self, status: str, metrics: Dict[str, Any]) -> None:
        self.write_live_artifacts(status=status, stage="finalization", metrics=metrics)
        self.close()

    def write_live_artifacts(self, *, status: str, stage: str, metrics: Dict[str, Any]) -> None:
        elapsed = self.elapsed_seconds()
        if self.total_count > 0 and self.total_target_violations > self.total_count:
            seconds_per_item = elapsed / self.total_count
            eta_seconds = round(seconds_per_item * (self.total_target_violations - self.total_count), 2)
        else:
            eta_seconds = 0.0
        percent_complete = (self.total_count / self.total_target_violations) if self.total_target_violations else 1.0

        progress_payload = {
            "status": status,
            "stage": stage,
            "started_at": self.started_at.isoformat(),
            "updated_at": utc_now_iso(),
            "elapsed_seconds": round(elapsed, 2),
            "processed_violations": self.total_count,
            "total_violations": self.total_target_violations,
            "percent_complete": round(percent_complete, 4),
            "eta_seconds": eta_seconds,
            "current_category": {
                "id": self.current_category_id,
                "label": self.current_category_label,
                "processed": self.current_category_done,
                "total": self.current_category_total,
            },
            "overall_partial": {
                "with_context": self.total_with,
                "without_context": self.total_without,
                "rate_with_context": round((self.total_with / self.total_count) if self.total_count else 0.0, 4),
                "rate_without_context": round((self.total_without / self.total_count) if self.total_count else 0.0, 4),
            },
            "sample_count": self.sample_count,
        }

        partial_payload = {
            "generated_at": utc_now_iso(),
            "status": status,
            "benchmark_root": self.benchmark_root.as_posix(),
            "ground_truth_file": self.truth_path.as_posix(),
            "ground_truth_schema": self.truth_schema,
            "selection": self.selection_cfg,
            "coverage_by_category": self.coverage_by_category,
            "metrics": {
                **metrics,
                "overall_partial": {
                    "count": self.total_count,
                    "with_context": self.total_with,
                    "without_context": self.total_without,
                    "rate_with_context": round((self.total_with / self.total_count) if self.total_count else 0.0, 4),
                    "rate_without_context": round((self.total_without / self.total_count) if self.total_count else 0.0, 4),
                },
            },
            "sample_count": self.sample_count,
        }

        write_json(self.progress_path, progress_payload)
        write_json(self.partial_metrics_path, partial_payload)
