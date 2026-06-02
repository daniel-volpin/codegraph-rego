from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_OUTPUT_DIR = "outputs/reporting/latest"
SUPPORT_TIERS = {
    "full": ["ISO-A.10-WEAK-HASH", "ISO-A.10-WEAK-RANDOM"],
    "guarded": ["ISO-A.10-WEAK-CRYPTO"],
    "manual": [
        "ISO-A.8-SQL-INJECTION",
        "ISO-A.8-PATH-TRAVERSAL",
        "ISO-A.8-CMD-INJECTION",
        "ISO-A.8-LDAP-INJECTION",
        "ISO-A.8-XPATH-INJECTION",
        "ISO-A.9.4.1",
        "ISO-A.12.4.1",
    ],
}


@dataclass(frozen=True)
class RunSpec:
    run_id: str
    stage: str
    label: str
    path: str
    compare_to: str | None = None


DEFAULT_RUN_SPECS = [
    RunSpec(
        run_id="thesis_final_detection",
        stage="detection",
        label="Authoritative Detection Baseline",
        path="detection_calibration_path_precision_v4",
    ),
    RunSpec(
        run_id="thesis_final_explanation",
        stage="explanation",
        label="Authoritative Explanation Baseline",
        path="thesis_final_explanation_full",
    ),
    RunSpec(
        run_id="thesis_final_remediation",
        stage="remediation",
        label="Authoritative Supported Remediation",
        path="repro_supported_medium_branch_benchmarktest01017_fix",
    ),
    RunSpec(
        run_id="current_main_supported_regression",
        stage="remediation",
        label="Current Main Supported Remediation",
        path="final_full_remediation_current_main",
        compare_to="thesis_final_remediation",
    ),
    RunSpec(
        run_id="current_bounded_compile_backed",
        stage="remediation",
        label="Current Bounded Compile-Backed",
        path="span_edit_bounded_smoke_v2",
        compare_to="thesis_final_remediation",
    ),
]


def parse_run_arg(raw: str) -> RunSpec:
    parts = raw.split("|")
    if len(parts) not in {4, 5}:
        raise ValueError(f"Invalid --run value: {raw!r}")
    run_id, stage, path, label = parts[:4]
    compare_to = parts[4] if len(parts) == 5 and parts[4] else None
    return RunSpec(run_id=run_id, stage=stage, path=path, label=label, compare_to=compare_to)


def build_report(outputs_root: Path, specs: list[RunSpec]) -> dict[str, Any]:
    run_summaries = [summarize_run(outputs_root, spec) for spec in specs]
    comparisons = build_comparisons(run_summaries)
    return {
        "report_version": 2,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "outputs_root": str(outputs_root.resolve()),
        "support_tiers": SUPPORT_TIERS,
        "runs": run_summaries,
        "comparisons": comparisons,
        "case_studies": load_case_studies(outputs_root),
        "headlines": build_headlines(run_summaries, comparisons),
    }


def summarize_run(outputs_root: Path, spec: RunSpec) -> dict[str, Any]:
    artifact_path = artifact_path_for_run(outputs_root, spec)
    if not artifact_path.exists():
        return {
            "id": spec.run_id,
            "label": spec.label,
            "stage": spec.stage,
            "artifact_path": str(artifact_path),
            "generated_at": None,
            "status": "missing",
            "compare_to": spec.compare_to,
            "error": "artifact_not_found",
        }

    payload = load_json(artifact_path)
    if spec.stage == "detection":
        return summarize_detection(spec, artifact_path, payload)
    if spec.stage == "explanation":
        return summarize_explanation(spec, artifact_path, payload)
    if spec.stage == "remediation":
        return summarize_remediation(spec, artifact_path, payload)
    raise ValueError(f"Unsupported stage: {spec.stage}")


def summarize_detection(spec: RunSpec, artifact_path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    metrics = dict(payload.get("metrics") or {})
    overall = dict(metrics.pop("overall", {}))
    return base_summary(spec, artifact_path, payload) | {
        "summary": {
            "tp": overall.get("tp"),
            "fp": overall.get("fp"),
            "fn": overall.get("fn"),
            "tn": overall.get("tn"),
            "precision": round_metric(overall.get("precision")),
            "recall": round_metric(overall.get("recall")),
            "f1": round_metric(overall.get("f1")),
            "support": overall.get("support"),
            "selected_testcases": len(payload.get("selected_testcases") or []),
            "violation_count": payload.get("violation_count"),
        },
        "categories": metrics,
    }


def summarize_explanation(spec: RunSpec, artifact_path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    metrics = dict(payload.get("metrics") or {})
    overall = dict(metrics.pop("overall", {}))
    return base_summary(spec, artifact_path, payload) | {
        "summary": {
            "surfaced_tp_count": overall.get("count"),
            "citations_with_context": overall.get("with_context"),
            "citations_without_context": overall.get("without_context"),
            "citation_rate_with_context": round_metric(overall.get("rate_with_context")),
            "citation_rate_without_context": round_metric(overall.get("rate_without_context")),
            "sample_count": payload.get("sample_count"),
        },
        "categories": metrics,
    }


def summarize_remediation(spec: RunSpec, artifact_path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    results = list(payload.get("results") or [])
    derived_counts = derive_remediation_counts(results)
    attempted = first_int(payload.get("attempted"), len(results))
    fix_success = first_int(payload.get("fix_success"), derived_counts["policy_pass_count"])
    build_attempted = first_int(payload.get("build_attempted"), derived_counts["build_attempted"])
    build_success = first_int(payload.get("build_success"), derived_counts["build_success"])
    fix_success_rate = first_value(payload.get("fix_success_rate"), safe_ratio(fix_success, attempted))
    build_success_rate = first_value(payload.get("build_success_rate"), safe_ratio(build_success, build_attempted))

    return base_summary(spec, artifact_path, payload) | {
        "compare_to": spec.compare_to,
        "summary": {
            "attempted": attempted,
            "fix_success": fix_success,
            "fix_success_rate": round_metric(fix_success_rate),
            "structured_valid": first_int(payload.get("structured_valid"), derived_counts["structured_valid"]),
            "replacement_applied": first_int(payload.get("replacement_applied"), derived_counts["replacement_applied"]),
            "policy_pass_count": first_int(payload.get("policy_pass_count"), derived_counts["policy_pass_count"]),
            "build_attempted": build_attempted,
            "build_success": build_success,
            "build_success_rate": round_metric(build_success_rate),
            "verification_mode": "compile_backed" if build_attempted > 0 else "policy_only",
            "status_counts": derived_counts["status_counts"],
            "decision_counts": derived_counts["decision_counts"],
        },
    }


def build_comparisons(run_summaries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id = {item["id"]: item for item in run_summaries if item.get("status") == "ok"}
    comparisons: list[dict[str, Any]] = []
    for item in run_summaries:
        compare_to = item.get("compare_to")
        if not compare_to or item.get("status") != "ok":
            continue
        baseline = by_id.get(compare_to)
        if not baseline:
            continue
        summary = item["summary"]
        base_summary_data = baseline["summary"]
        comparisons.append(
            {
                "stage": item["stage"],
                "current_run_id": item["id"],
                "baseline_run_id": baseline["id"],
                "current_label": item["label"],
                "baseline_label": baseline["label"],
                "current_attempted": summary.get("attempted"),
                "baseline_attempted": base_summary_data.get("attempted"),
                "delta": {
                    "attempted": summary.get("attempted", 0) - base_summary_data.get("attempted", 0),
                    "fix_success": summary.get("fix_success", 0) - base_summary_data.get("fix_success", 0),
                    "fix_success_rate_points": percent_points(
                        summary.get("fix_success_rate"), base_summary_data.get("fix_success_rate")
                    ),
                    "build_success": summary.get("build_success", 0) - base_summary_data.get("build_success", 0),
                    "build_success_rate_points": percent_points(
                        summary.get("build_success_rate"), base_summary_data.get("build_success_rate")
                    ),
                    "structured_valid": summary.get("structured_valid", 0)
                    - base_summary_data.get("structured_valid", 0),
                    "replacement_applied": summary.get("replacement_applied", 0)
                    - base_summary_data.get("replacement_applied", 0),
                },
            }
        )
    return comparisons


def build_headlines(run_summaries: list[dict[str, Any]], comparisons: list[dict[str, Any]]) -> list[dict[str, Any]]:
    headlines: list[dict[str, Any]] = []
    by_id = {item["id"]: item for item in run_summaries if item.get("status") == "ok"}

    detection = by_id.get("thesis_final_detection")
    if detection:
        summary = detection["summary"]
        headlines.append(
            {
                "audiences": ["thesis", "pr", "supervisor", "product"],
                "text": (
                    "Authoritative benchmark detection reports precision "
                    f"{summary['precision']:.4f}, recall {summary['recall']:.4f}, and F1 {summary['f1']:.4f} "
                    f"across {summary['support']} selected benchmark cases."
                ),
            }
        )

    explanation = by_id.get("thesis_final_explanation")
    if explanation:
        summary = explanation["summary"]
        headlines.append(
            {
                "audiences": ["thesis", "pr", "supervisor"],
                "text": (
                    "Authoritative benchmark explanation reaches Citation@Context "
                    f"{summary['citation_rate_with_context']:.4f} and Citation@NoContext "
                    f"{summary['citation_rate_without_context']:.4f} across {summary['surfaced_tp_count']} "
                    "surfaced true positives."
                ),
            }
        )

    thesis_remediation = by_id.get("thesis_final_remediation")
    if thesis_remediation:
        summary = thesis_remediation["summary"]
        headlines.append(
            {
                "audiences": ["thesis", "supervisor", "product"],
                "text": (
                    "Authoritative benchmark remediation reaches "
                    f"{summary['build_success']}/{summary['attempted']} fully verified compile-backed fixes "
                    f"({summary['build_success_rate']:.4f})."
                ),
            }
        )

    for comparison in comparisons:
        current = by_id.get(comparison["current_run_id"])
        if not current or current["stage"] != "remediation":
            continue
        summary = current["summary"]
        if summary["build_attempted"] <= 0:
            continue
        headlines.append(
            {
                "audiences": ["thesis", "pr", "supervisor", "product"],
                "text": (
                    f"{current['label']} reaches {summary['build_success']}/{summary['attempted']} fully verified "
                    f"fixes ({summary['build_success_rate']:.4f}), a "
                    f"{comparison['delta']['fix_success_rate_points']:+.2f} point change in fix-success rate versus "
                    f"{comparison['baseline_label']} on {summary['attempted']} attempted cases."
                ),
            }
        )

    return headlines


def render_markdown(report: dict[str, Any]) -> str:
    support_tiers = dict(SUPPORT_TIERS)
    support_tiers.update(report.get("support_tiers") or {})
    lines = [
        "# Benchmark Reporting Summary",
        "",
        f"- Generated at: `{report['generated_at']}`",
        f"- Outputs root: `{report['outputs_root']}`",
        "",
        "## Support Tiers",
        "",
        f"- Full: `{', '.join(support_tiers['full'])}`",
        f"- Guarded: `{', '.join(support_tiers['guarded'])}`",
        f"- Manual: `{', '.join(support_tiers['manual'])}`",
        "",
        "## Headline Summary",
        "",
    ]

    if report["headlines"]:
        for item in report["headlines"]:
            lines.append(f"- {item['text']}")
    else:
        lines.append("- No headline summaries available.")

    lines.extend(["", "## Run Summaries", ""])
    for run in report["runs"]:
        lines.extend(render_run_summary(run))

    lines.extend(["## Headline Comparisons", ""])
    if report["comparisons"]:
        lines.extend(render_comparison_table(report["comparisons"]))
    else:
        lines.append("- No comparable runs were available.")
    case_studies = report.get("case_studies") or []
    lines.extend(["", "## Case Study Observations", ""])
    if case_studies:
        for item in case_studies:
            lines.append(f"### {item.get('name', 'Unnamed Case Study')}")
            lines.append("")
            lines.append(f"- Status: `{item.get('status', 'unknown')}`")
            if item.get("repo"):
                lines.append(f"- Source: `{item['repo']}`")
            if item.get("observations"):
                for obs in item["observations"]:
                    lines.append(f"- {obs}")
            lines.append("")
    else:
        lines.append("- No case-study observations have been recorded yet.")
    lines.append("")
    return "\n".join(lines)


def write_report(report: dict[str, Any], output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    report_json = output_dir / "report.json"
    report_md = output_dir / "report.md"
    report_json.write_text(json.dumps(report, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    report_md.write_text(render_markdown(report), encoding="utf-8")
    return report_json, report_md


def artifact_path_for_run(outputs_root: Path, spec: RunSpec) -> Path:
    base = Path(spec.path)
    if not base.is_absolute():
        base = outputs_root / base
    artifact_names = {
        "detection": "metrics.json",
        "explanation": "citation_metrics.json",
        "remediation": "remediation_metrics.json",
    }
    try:
        return base / artifact_names[spec.stage]
    except KeyError as exc:
        raise ValueError(f"Unsupported stage: {spec.stage}") from exc


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_case_studies(outputs_root: Path) -> list[dict[str, Any]]:
    index_path = outputs_root / "case_studies" / "index.json"
    if not index_path.exists():
        return []
    payload = load_json(index_path)
    case_studies = payload.get("case_studies")
    if not isinstance(case_studies, list):
        return []
    return [item for item in case_studies if isinstance(item, dict)]


def base_summary(spec: RunSpec, artifact_path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": spec.run_id,
        "label": spec.label,
        "stage": spec.stage,
        "artifact_path": str(artifact_path),
        "generated_at": payload.get("generated_at"),
        "status": "ok",
        "sample_overview": sample_overview(payload.get("selection") or {}, payload.get("coverage_by_category") or {}),
    }


def sample_overview(selection: dict[str, Any], coverage_by_category: dict[str, Any]) -> dict[str, Any]:
    sampled = sum(1 for item in coverage_by_category.values() if item.get("sampled"))
    fully_included = sum(1 for item in coverage_by_category.values() if not item.get("sampled"))
    return {
        "max_cases_per_category": selection.get("max_cases_per_category"),
        "seed": selection.get("seed"),
        "category_count": len(selection.get("categories") or []),
        "sampled_categories": sampled,
        "fully_included_categories": fully_included,
    }


def derive_remediation_counts(results: list[dict[str, Any]]) -> dict[str, Any]:
    status_counts = Counter(str(item.get("status") or "UNKNOWN") for item in results)
    decision_counts = Counter(str((item.get("generation") or {}).get("decision") or "UNKNOWN") for item in results)
    structured_valid = sum(
        1
        for item in results
        if isinstance(item.get("generation"), dict) and item["generation"].get("raw_response_valid")
    )
    replacement_applied = sum(1 for item in results if item.get("patch_applied") is True)
    policy_pass_count = sum(1 for item in results if item.get("policy_pass") is True)
    build_attempted = sum(1 for item in results if item.get("build_pass") is not None)
    build_success = sum(1 for item in results if item.get("build_pass") is True)
    return {
        "status_counts": dict(sorted(status_counts.items())),
        "decision_counts": dict(sorted(decision_counts.items())),
        "structured_valid": structured_valid,
        "replacement_applied": replacement_applied,
        "policy_pass_count": policy_pass_count,
        "build_attempted": build_attempted,
        "build_success": build_success,
    }


def render_run_summary(run: dict[str, Any]) -> list[str]:
    lines = [
        f"### {run['label']}",
        "",
        f"- Stage: `{run['stage']}`",
        f"- Artifact: `{run['artifact_path']}`",
    ]
    if run["status"] != "ok":
        lines.append(f"- Status: `{run['status']}` ({run.get('error', 'unknown_error')})")
        lines.append("")
        return lines

    summary = run["summary"]
    renderers = {
        "detection": render_detection_summary,
        "explanation": render_explanation_summary,
        "remediation": render_remediation_summary,
    }
    lines.extend(renderers[run["stage"]](summary))
    lines.append("")
    return lines


def render_detection_summary(summary: dict[str, Any]) -> list[str]:
    return [
        f"- Precision: `{format_rate(summary['precision'])}`",
        f"- Recall: `{format_rate(summary['recall'])}`",
        f"- F1: `{format_rate(summary['f1'])}`",
        f"- TP / FP / FN: `{summary['tp']}` / `{summary['fp']}` / `{summary['fn']}`",
        f"- Selected cases: `{summary['support']}`",
        f"- Violations surfaced: `{summary['violation_count']}`",
    ]


def render_explanation_summary(summary: dict[str, Any]) -> list[str]:
    return [
        f"- Surfaced true positives evaluated: `{summary['surfaced_tp_count']}`",
        f"- Citation@Context: `{format_rate(summary['citation_rate_with_context'])}`",
        f"- Citation@NoContext: `{format_rate(summary['citation_rate_without_context'])}`",
        f"- Sample count: `{summary['sample_count']}`",
    ]


def render_remediation_summary(summary: dict[str, Any]) -> list[str]:
    fully_verified_rate = (
        "not_attempted"
        if summary["verification_mode"] == "policy_only" and summary["build_attempted"] == 0
        else format_rate(summary["build_success_rate"])
    )
    return [
        f"- Verification mode: `{summary['verification_mode']}`",
        f"- Attempted: `{summary['attempted']}`",
        f"- Structured valid: `{summary['structured_valid']}`",
        f"- Replacement applied: `{summary['replacement_applied']}`",
        f"- Policy fixed: `{summary['policy_pass_count']}`",
        f"- Fully verified success rate: `{fully_verified_rate}`",
        f"- Fix success rate: `{format_rate(summary['fix_success_rate'])}`",
        f"- Status counts: `{json.dumps(summary['status_counts'], sort_keys=True)}`",
    ]


def render_comparison_table(comparisons: list[dict[str, Any]]) -> list[str]:
    lines = [
        "| Stage | Current Run | Baseline Run | Current Attempted | Baseline Attempted | Attempted Delta | Fix Success Delta | Fix Success Rate Delta (pts) | Build Success Delta | Build Success Rate Delta (pts) |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for item in comparisons:
        delta = item["delta"]
        lines.append(
            "| "
            + " | ".join(
                [
                    item["stage"],
                    item["current_label"],
                    item["baseline_label"],
                    str(item["current_attempted"]),
                    str(item["baseline_attempted"]),
                    str(delta["attempted"]),
                    str(delta["fix_success"]),
                    str(delta["fix_success_rate_points"]),
                    str(delta["build_success"]),
                    str(delta["build_success_rate_points"]),
                ]
            )
            + " |"
        )
    return lines


def round_metric(value: float | None) -> float | None:
    if value is None:
        return None
    return round(float(value), 4)


def percent_points(current: float | None, baseline: float | None) -> float | None:
    if current is None or baseline is None:
        return None
    return round((current - baseline) * 100.0, 2)


def safe_ratio(numerator: int, denominator: int) -> float | None:
    if denominator <= 0:
        return None
    return round(numerator / denominator, 4)


def format_rate(value: float | None) -> str:
    if value is None:
        return "-"
    return f"{value:.4f}"


def first_int(primary: Any, fallback: int) -> int:
    if primary is None:
        return int(fallback)
    return int(primary)


def first_value(primary: Any, fallback: Any) -> Any:
    if primary is None:
        return fallback
    return primary
