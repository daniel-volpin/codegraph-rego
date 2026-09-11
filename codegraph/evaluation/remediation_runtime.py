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
from codegraph.evaluation.io import (
    render_latex_table,
    render_markdown_table,
    write_csv,
    write_json,
)

TRACKED_FINAL_STATUSES: Sequence[str] = (
    "OK",
    "NO_FIX",
    "GENERATION_ERROR",
    "REPLACEMENT_ERROR",
    "BUILD_ERROR",
    "VERIFICATION_ERROR",
)

# Statuses where the system actually attempted to apply a remediation.
# Excluding NO_FIX (declared abstention) and SKIPPED (preflight failure)
# isolates "calibrated success probability on attempted fixes" from
# "knew-when-to-abstain" calibration over the full set.
ATTEMPTED_REMEDIATION_STATUSES: Sequence[str] = (
    "OK",
    "GENERATION_ERROR",
    "REPLACEMENT_ERROR",
    "BUILD_ERROR",
    "VERIFICATION_ERROR",
)

FULLY_VERIFIED_LABEL_DEFINITION = (
    "fully_verified := policy_fixed is true and build_success is true"
)


def _safe_float(value: Any) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if number < 0.0 or number > 1.0:
        return None
    return number


def is_fully_verified(item: Mapping[str, Any]) -> bool:
    value = item.get("fully_verified")
    if isinstance(value, bool):
        return value
    return item.get("policy_fixed") is True and item.get("build_success") is True


def _calibration_block(
    points: list[tuple[float, int]],
    cases: list[dict[str, Any]],
    missing_confidence_count: int,
    *,
    bins: int,
    population: str,
) -> dict[str, Any] | None:
    if not points:
        return None

    n = len(points)
    brier_score = sum((score - label) ** 2 for score, label in points) / n

    bucket_count = max(1, bins)
    buckets: list[list[tuple[float, int]]] = [[] for _ in range(bucket_count)]
    for score, label in points:
        index = min(int(score * bucket_count), bucket_count - 1)
        buckets[index].append((score, label))

    ece = 0.0
    reliability_bins: list[dict[str, Any]] = []
    for idx, bucket in enumerate(buckets):
        if not bucket:
            continue
        count = len(bucket)
        avg_confidence = sum(score for score, _ in bucket) / count
        empirical_success = sum(label for _, label in bucket) / count
        gap = abs(avg_confidence - empirical_success)
        ece += (count / n) * gap
        reliability_bins.append(
            {
                "bin_start": round(idx / bucket_count, 4),
                "bin_end": round((idx + 1) / bucket_count, 4),
                "count": count,
                "avg_confidence": round(avg_confidence, 4),
                "empirical_success": round(empirical_success, 4),
                "gap": round(gap, 4),
            }
        )

    ranked = sorted(points, key=lambda pair: pair[0], reverse=True)
    checkpoints = [0.25, 0.5, 0.75, 1.0]
    risk_coverage: list[dict[str, Any]] = []
    for checkpoint in checkpoints:
        k = max(1, int(round(n * checkpoint)))
        subset = ranked[:k]
        success_rate = sum(label for _, label in subset) / k
        risk_coverage.append(
            {
                "coverage": round(k / n, 4),
                "success_rate": round(success_rate, 4),
                "risk": round(1.0 - success_rate, 4),
            }
        )

    return {
        "population": population,
        "count": n,
        "missing_confidence_count": missing_confidence_count,
        "label": "fully_verified",
        "label_definition": FULLY_VERIFIED_LABEL_DEFINITION,
        "positive_count": sum(label for _, label in points),
        "negative_count": n - sum(label for _, label in points),
        "brier_score": round(brier_score, 6),
        "ece": round(ece, 6),
        "reliability_bins": reliability_bins,
        "risk_coverage": risk_coverage,
        "cases": cases,
    }


def _collect_calibration_points(
    results: Sequence[Mapping[str, Any]],
    *,
    status_filter: set[str] | None = None,
) -> tuple[list[tuple[float, int]], list[dict[str, Any]], int]:
    points: list[tuple[float, int]] = []
    cases: list[dict[str, Any]] = []
    missing_confidence_count = 0
    for item in results:
        if status_filter is not None:
            status = str(item.get("status") or "")
            if status not in status_filter:
                continue
        confidence = item.get("confidence") or {}
        score = _safe_float((confidence or {}).get("score"))
        if score is None:
            missing_confidence_count += 1
            continue
        label = 1 if is_fully_verified(item) else 0
        points.append((score, label))
        cases.append(
            {
                "case_id": item.get("case_id"),
                "violation_id": item.get("violation_id"),
                "status": item.get("status"),
                "confidence_score": score,
                "confidence_band": confidence.get("band"),
                "fully_verified": bool(label),
                "policy_fixed": item.get("policy_fixed"),
                "build_success": item.get("build_success"),
            }
        )
    return points, cases, missing_confidence_count


def build_confidence_calibration(
    results: Sequence[Mapping[str, Any]],
    *,
    bins: int = 10,
) -> dict[str, Any] | None:
    """Compute confidence calibration over the remediation results.

    The top-level fields (``count``, ``brier_score``, ``ece``,
    ``reliability_bins``, ``risk_coverage``, ``cases``) describe the
    full population. The ``populations`` sub-block additionally exposes
    ``full``, ``attempted_only`` (status in
    :data:`ATTEMPTED_REMEDIATION_STATUSES`), and ``no_fix_only``
    (declared abstentions). Reporting all three separates calibrated
    success probability from knew-when-to-abstain calibration.
    """
    full_points, full_cases, full_missing = _collect_calibration_points(results)
    full = _calibration_block(full_points, full_cases, full_missing, bins=bins, population="full")
    if full is None:
        return None

    attempted_filter = set(ATTEMPTED_REMEDIATION_STATUSES)
    a_points, a_cases, a_missing = _collect_calibration_points(results, status_filter=attempted_filter)
    attempted = _calibration_block(a_points, a_cases, a_missing, bins=bins, population="attempted_only")

    n_points, n_cases, n_missing = _collect_calibration_points(results, status_filter={"NO_FIX"})
    no_fix = _calibration_block(n_points, n_cases, n_missing, bins=bins, population="no_fix_only")

    return {
        **full,  # legacy top-level fields = full population (backward compatible)
        "populations": {
            "full": full,
            "attempted_only": attempted,
            "no_fix_only": no_fix,
        },
    }


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


def render_calibration_markdown(calibration: Mapping[str, Any]) -> str:
    lines = [
        "# Remediation Calibration",
        "",
        "Headline numbers below are computed over the **full** population (every "
        "result that carries a confidence score, including `NO_FIX` abstentions). "
        "The per-population breakdown distinguishes calibrated success "
        "probability from knew-when-to-abstain behavior.",
        "",
        f"- Cases with confidence: `{calibration.get('count', 0)}`",
        f"- Missing confidence: `{calibration.get('missing_confidence_count', 0)}`",
        f"- Label: `{calibration.get('label', 'fully_verified')}`",
        f"- Label definition: `{calibration.get('label_definition', FULLY_VERIFIED_LABEL_DEFINITION)}`",
        f"- Positive labels: `{calibration.get('positive_count', 0)}`",
        f"- Negative labels: `{calibration.get('negative_count', 0)}`",
        f"- Brier score (full): `{calibration.get('brier_score', 'n/a')}`",
        f"- ECE (full): `{calibration.get('ece', 'n/a')}`",
        "",
        "## Reliability Bins (full population)",
        "",
        render_markdown_table(
            ["Bin", "Count", "Avg confidence", "Empirical success", "Gap"],
            [
                [
                    f"{item.get('bin_start')}-{item.get('bin_end')}",
                    item.get("count"),
                    item.get("avg_confidence"),
                    item.get("empirical_success"),
                    item.get("gap"),
                ]
                for item in calibration.get("reliability_bins", [])
            ],
        ).rstrip(),
    ]

    populations = calibration.get("populations") if isinstance(calibration, Mapping) else None
    if isinstance(populations, Mapping):
        rows = []
        for name in ("full", "attempted_only", "no_fix_only"):
            block = populations.get(name)
            if not isinstance(block, Mapping):
                rows.append([name, "0", "n/a", "n/a", "n/a", "n/a"])
                continue
            rows.append(
                [
                    name,
                    block.get("count", 0),
                    block.get("positive_count", 0),
                    block.get("negative_count", 0),
                    block.get("brier_score", "n/a"),
                    block.get("ece", "n/a"),
                ]
            )
        lines.extend(
            [
                "",
                "## Calibration by Population",
                "",
                render_markdown_table(
                    ["Population", "Count", "Positive", "Negative", "Brier", "ECE"],
                    rows,
                ).rstrip(),
                "",
                "Population definitions:",
                "- `full`: every result with a confidence score (legacy headline).",
                "- `attempted_only`: results where the system attempted to apply a"
                " remediation (status in OK / GENERATION_ERROR / REPLACEMENT_ERROR /"
                " BUILD_ERROR / VERIFICATION_ERROR).",
                "- `no_fix_only`: declared-abstention cases (status NO_FIX).",
            ]
        )

    return "\n".join(lines) + "\n"


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
