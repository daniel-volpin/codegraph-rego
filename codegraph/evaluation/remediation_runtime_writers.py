from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from codegraph.evaluation.calibration import build_confidence_calibration, render_calibration_markdown
from codegraph.evaluation.io import render_latex_table, render_markdown_table, write_csv, write_json
from codegraph.evaluation.remediation_runtime_helpers import (
    TRACKED_FINAL_STATUSES,
    build_stage_counts,
    tracked_status_counts,
    untracked_status_counts,
    utc_now_iso,
)
from codegraph.llm.usage import usage_snapshot


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
    write_json(output_dir / "model_usage.json", usage_snapshot())
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
