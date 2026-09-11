"""Evaluation package for benchmark datasets, metrics, and calibration analysis."""

from __future__ import annotations

from codegraph.evaluation.calibration import (
    ATTEMPTED_REMEDIATION_STATUSES,
    FULLY_VERIFIED_LABEL_DEFINITION,
    build_confidence_calibration,
    is_fully_verified,
    render_calibration_markdown,
)
from codegraph.evaluation.remediation_runtime import (
    TRACKED_FINAL_STATUSES,
    RemediationRuntime,
    build_case_id,
    build_metrics_payload,
    build_remediation_result,
    build_skipped_result,
    build_stage_counts,
    tracked_status_counts,
    untracked_status_counts,
    utc_now_iso,
    write_final_artifacts,
)

__all__ = [
    "ATTEMPTED_REMEDIATION_STATUSES",
    "FULLY_VERIFIED_LABEL_DEFINITION",
    "TRACKED_FINAL_STATUSES",
    "RemediationRuntime",
    "build_case_id",
    "build_confidence_calibration",
    "build_metrics_payload",
    "build_remediation_result",
    "build_skipped_result",
    "build_stage_counts",
    "is_fully_verified",
    "render_calibration_markdown",
    "tracked_status_counts",
    "untracked_status_counts",
    "utc_now_iso",
    "write_final_artifacts",
]
