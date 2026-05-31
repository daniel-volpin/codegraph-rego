"""Build thesis evidence tables and machine-readable audit artifacts."""

from __future__ import annotations

import csv
import json
import math
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

ROOT = Path(__file__).resolve().parents[2]
OUTPUTS = ROOT / "outputs"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def git_sha() -> str | None:
    proc = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=False)
    return proc.stdout.strip() if proc.returncode == 0 else None


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: Iterable[Mapping[str, Any]], fieldnames: Sequence[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field) for field in fieldnames})


def md_table(headers: Sequence[str], rows: Iterable[Sequence[Any]]) -> str:
    out = ["| " + " | ".join(headers) + " |", "| " + " | ".join(["---"] * len(headers)) + " |"]
    out.extend("| " + " | ".join(str(cell) for cell in row) + " |" for row in rows)
    return "\n".join(out) + "\n"


def tex_escape(value: Any) -> str:
    text = str(value)
    return (
        text.replace("\\", r"\textbackslash{}")
        .replace("&", r"\&")
        .replace("%", r"\%")
        .replace("$", r"\$")
        .replace("#", r"\#")
        .replace("_", r"\_")
        .replace("{", r"\{")
        .replace("}", r"\}")
    )


def tex_table(
    headers: Sequence[str],
    rows: Iterable[Sequence[Any]],
    *,
    caption: str | None = None,
    label: str | None = None,
    footnote: str | None = None,
) -> str:
    column_format = "l" + "r" * (len(headers) - 1)
    lines: list[str] = []
    if caption:
        lines.extend([r"\begin{table}[h]", r"\centering"])
    lines.extend([rf"\begin{{tabular}}{{{column_format}}}", r"\hline"])
    lines.append(" & ".join(tex_escape(h) for h in headers) + r" \\")
    lines.append(r"\hline")
    for row in rows:
        lines.append(" & ".join(tex_escape(c) for c in row) + r" \\")
    lines.extend([r"\hline", r"\end{tabular}"])
    if footnote:
        lines.append(r"\begin{minipage}{0.95\linewidth}")
        lines.append(r"\footnotesize " + tex_escape(footnote))
        lines.append(r"\end{minipage}")
    if caption:
        lines.append(r"\caption{" + tex_escape(caption) + "}")
        if label:
            lines.append(r"\label{" + tex_escape(label) + "}")
        lines.append(r"\end{table}")
    return "\n".join(lines) + "\n"


def provenance_summary(path: Path | None) -> dict[str, Any]:
    if not path or not path.exists():
        return {"exists": False, "path": str(path) if path else None}
    data = read_json(path)
    llm = data.get("llm") or {}
    return {
        "exists": True,
        "path": path.as_posix(),
        "git_sha": (data.get("git") or {}).get("sha"),
        "seed": data.get("seed"),
        "model": llm.get("remediation_model") or llm.get("model"),
        "config": (data.get("config") or {}).get("path"),
        "generated_at": data.get("generated_at"),
    }


def detection_artifacts() -> dict[str, Any]:
    out_dir = OUTPUTS / "thesis_final_detection_full_v2"
    metrics_path = out_dir / "metrics.json"
    metrics = read_json(metrics_path)
    rows_csv = read_csv(out_dir / "metrics.csv")
    rows = [
        [r["category"], r["tp"], r["fp"], r["fn"], r["precision"], r["recall"], r["f1"]]
        for r in rows_csv
    ]
    headers = ["Category", "TP", "FP", "FN", "Precision", "Recall", "F1"]
    caption = (
        "Detection performance on the selected OWASP Benchmark eight-CWE evaluation set (n=454). "
        "Per-CWE rows evaluate each category against its mapped Rego rule(s); the Overall row is "
        "recomputed over the selected testcase union using any evaluated rule firing as the positive prediction."
    )
    footnote = (
        "Because a benign testcase selected under one CWE can fire an off-target rule from another CWE, the Overall "
        "row is not the arithmetic sum of per-CWE rows. Summing category rows gives FP=9/TN=212; the union any-rule "
        "Overall row gives FP=11/TN=210. violation_count=255 counts emitted rule violations and is not used as the "
        "confusion-matrix denominator."
    )
    write_text(out_dir / "table.tex", tex_table(headers, rows, caption="Benchmark Evaluation Metrics"))
    semantic_md = caption + "\n\n" + md_table(headers, rows) + "\n" + footnote + "\n"
    write_text(out_dir / "table_with_semantics.md", semantic_md)
    write_text(
        out_dir / "table_with_semantics.tex",
        tex_table(headers, rows, caption=caption, label="tab:detection-selected-eight-cwe", footnote=footnote),
    )

    coverage = metrics["coverage_by_category"]
    total_available = sum(v["available_cases"] for v in coverage.values())
    total_selected = sum(v["selected_cases"] for v in coverage.values())
    selection_summary = {
        "generated_at": now_iso(),
        "source_metrics": metrics_path.as_posix(),
        "available_cases_per_category": {k: v["available_cases"] for k, v in coverage.items()},
        "selected_cases_per_category": {k: v["selected_cases"] for k, v in coverage.items()},
        "sampled_per_category": {k: v["sampled"] for k, v in coverage.items()},
        "seed": metrics["selection"].get("seed"),
        "max_cases_per_category": metrics["selection"].get("max_cases_per_category"),
        "total_available": total_available,
        "total_selected": total_selected,
        "selected_fraction": total_selected / total_available if total_available else None,
    }
    write_json(out_dir / "selection_summary.json", selection_summary)

    sums = {"tp": 0, "fp": 0, "tn": 0, "fn": 0}
    for key, value in metrics["metrics"].items():
        if key == "overall":
            continue
        for field in sums:
            sums[field] += int(value[field])
    overall = metrics["metrics"]["overall"]
    return {
        "overall": {k: overall[k] for k in ("tp", "fp", "tn", "fn", "precision", "recall", "f1", "support")},
        "category_row_sums": sums,
        "violation_count": metrics.get("violation_count"),
        "selection": selection_summary,
        "provenance": provenance_summary(out_dir / "provenance.json"),
    }


def explanation_artifacts() -> dict[str, Any]:
    out_dir = OUTPUTS / "pr_full_verification_2026-05-11" / "explanation_full"
    metrics = read_json(out_dir / "citation_metrics.json")
    rows_csv = read_csv(out_dir / "citation_metrics.csv")
    headers = ["Category", "TP Count", "Citation@TP (ctx)", "Citation@TP (no-ctx)", "FP Count", "Citation@FP (ctx)", "Citation@FP (no-ctx)"]
    rows = [
        [
            r["category"],
            r["tp_count"],
            r["citation_at_tp_with_context"],
            r["citation_at_tp_without_context"],
            r["fp_count"],
            r["citation_at_fp_with_context"],
            r["citation_at_fp_without_context"],
        ]
        for r in rows_csv
    ]
    write_text(out_dir / "table.md", md_table(headers, rows))
    write_text(out_dir / "table.tex", tex_table(headers, rows, caption="Citation-style attribution for structured explanations"))
    summary = {
        "generated_at": now_iso(),
        "source_metrics": (out_dir / "citation_metrics.json").as_posix(),
        "safe_wording": (
            "Explanation evaluation measures citation-style attribution in structured explanations, not semantic "
            "correctness of the natural-language rationale. In the provenance-backed PR verification run, all 222 "
            "TP explanations and all 9 FP explanations cited the supplied evidence with context; no no-context "
            "TP/FP output cited the evidence."
        ),
        "metrics": metrics["metrics"]["overall"],
        "request_metrics_lines": sum(1 for _ in (out_dir / "request_metrics.jsonl").open(encoding="utf-8")),
        "sample_lines": sum(1 for _ in (out_dir / "explanation_samples.jsonl").open(encoding="utf-8")),
        "provenance": provenance_summary(out_dir / "provenance.json"),
    }
    write_json(out_dir / "explanation_summary_for_thesis.json", summary)
    return summary


def remediation_dir_summary(path: Path) -> dict[str, Any]:
    metrics_path = path / "remediation_metrics.json"
    if not metrics_path.exists():
        failed_path = path / "FAILED_RUN.md"
        return {
            "path": path.as_posix(),
            "exists": False,
            "failure_recorded": failed_path.exists(),
            "failed_run_path": failed_path.as_posix() if failed_path.exists() else None,
        }
    metrics = read_json(metrics_path)
    calibration_path = path / "confidence_calibration.json"
    calibration = read_json(calibration_path) if calibration_path.exists() else None
    summary_path = path / "summary.md"
    summary_text = summary_path.read_text(encoding="utf-8") if summary_path.exists() else ""
    summary_conflict = False
    if calibration and summary_text:
        brier = calibration.get("brier_score")
        ece = calibration.get("ece")
        summary_conflict = (
            brier is not None
            and f"`{brier}`" not in summary_text
            or ece is not None
            and f"`{ece}`" not in summary_text
        )
    prov = provenance_summary(path / "provenance.json")
    return {
        "path": path.as_posix(),
        "exists": True,
        "metrics_path": metrics_path.as_posix(),
        "attempted": metrics.get("attempted"),
        "fix_success": metrics.get("fix_success"),
        "structured_valid": metrics.get("structured_valid"),
        "replacement_applied": metrics.get("replacement_applied"),
        "policy_pass_count": metrics.get("policy_pass_count"),
        "build_attempted": metrics.get("build_attempted"),
        "build_success": metrics.get("build_success"),
        "fix_success_rate": metrics.get("fix_success_rate"),
        "build_success_rate": metrics.get("build_success_rate"),
        "confidence_calibration": metrics.get("confidence_calibration") or calibration,
        "final_status_counts": metrics.get("final_status_counts"),
        "selection": metrics.get("selection"),
        "provenance": prov,
        "summary_md_conflicts_with_json": summary_conflict,
    }


def remediation_report() -> dict[str, Any]:
    report = {
        "generated_at": now_iso(),
        "runs": {
            "v2": remediation_dir_summary(OUTPUTS / "thesis_final_remediation_v2"),
            "v3": remediation_dir_summary(OUTPUTS / "thesis_final_remediation_v3"),
            "pr_full_verification_2026_05_11": remediation_dir_summary(
                OUTPUTS / "pr_full_verification_2026-05-11" / "remediation_supported_medium"
            ),
            "repro_2026_05_31": remediation_dir_summary(OUTPUTS / "thesis_final_remediation_repro_2026-05-31"),
        },
        "canonical_recommendation": (
            "Use the provenance-backed PR verification run as the reproducibility check. Treat v2 25/25 as a "
            "historical metric artifact unless it is regenerated with exact-run provenance."
        ),
    }
    write_json(OUTPUTS / "remediation_canonicality_report_2026-05-31.json", report)
    lines = [
        "# Remediation Canonicality Report",
        "",
        report["canonical_recommendation"],
        "",
        "| Run | Attempted | Fully verified | Success rate | Brier | ECE | Provenance | Model | Summary conflict |",
        "|---|---:|---:|---:|---:|---:|---|---|---|",
    ]
    for name, run in report["runs"].items():
        if run.get("failure_recorded"):
            lines.append(
                f"| {name} | failed before metrics | failed before metrics | n/a | n/a | n/a | no | n/a | failed run recorded: {run.get('failed_run_path')} |"
            )
            continue
        cal = run.get("confidence_calibration") or {}
        prov = run.get("provenance") or {}
        lines.append(
            "| {name} | {attempted} | {fixed} | {rate} | {brier} | {ece} | {prov} | {model} | {conflict} |".format(
                name=name,
                attempted=run.get("attempted"),
                fixed=run.get("fix_success"),
                rate=run.get("fix_success_rate"),
                brier=cal.get("brier_score"),
                ece=cal.get("ece"),
                prov="yes" if prov.get("exists") else "no",
                model=prov.get("model"),
                conflict=run.get("summary_md_conflicts_with_json"),
            )
        )
    write_text(OUTPUTS / "remediation_canonicality_report_2026-05-31.md", "\n".join(lines) + "\n")
    return report


def mark_v2_summary_stale_if_needed(report: dict[str, Any]) -> None:
    v2 = report["runs"]["v2"]
    if not v2.get("summary_md_conflicts_with_json"):
        return
    path = OUTPUTS / "thesis_final_remediation_v2" / "STALE_SUMMARY_DO_NOT_CITE.md"
    write_text(
        path,
        "# Stale Summary Warning\n\n"
        "`summary.md` disagrees with `remediation_metrics.json` and `confidence_calibration.json` for confidence "
        "calibration values. Cite `remediation_metrics.json` and `confidence_calibration.json`; do not cite the stale "
        "summary for Brier/ECE.\n",
    )


def normalize_f10_dir(path: Path) -> dict[str, Any]:
    if (path / "detection_per_case.json").exists():
        data = read_json(path / "detection_per_case.json")
        if "metrics" in data:
            metrics = data["metrics"]
            rows = [
                {
                    "scope": "overall",
                    "method": method,
                    **{k: metrics[method].get(k) for k in ("tp", "fp", "tn", "fn", "precision", "recall", "f1")},
                }
                for method in metrics
            ]
            table_rows = [[r["method"], r["tp"], r["fp"], r["tn"], r["fn"], r["precision"], r["recall"], r["f1"]] for r in rows]
            title = f"LexicalNoiseJava metrics ({data.get('benchmark_id')}, n={data.get('n_cases')})"
        else:
            metrics = data["overall"]
            rows = [
                {
                    "scope": "overall",
                    "method": method,
                    **{k: metrics[method].get(k) for k in ("tp", "fp", "tn", "fn", "precision", "recall", "f1")},
                }
                for method in metrics
            ]
            for cwe, per_method in data.get("per_cwe", {}).items():
                for method, values in per_method.items():
                    rows.append(
                        {
                            "scope": f"CWE-{cwe}",
                            "method": method,
                            **{k: values.get(k) for k in ("tp", "fp", "tn", "fn", "precision", "recall", "f1")},
                        }
                    )
            table_rows = [[r["method"], r["tp"], r["fp"], r["tn"], r["fn"], r["precision"], r["recall"], r["f1"]] for r in rows if r["scope"] == "overall"]
            title = f"OWASP file-level F10 metrics ({data.get('benchmark_id')}, n={data.get('n_cases')})"
        normalized = {
            "generated_at": now_iso(),
            "source": (path / "detection_per_case.json").as_posix(),
            "benchmark_id": data.get("benchmark_id"),
            "n_cases": data.get("n_cases"),
            "metrics": metrics,
            "paired": data.get("paired", []),
            "per_stratum": data.get("per_stratum"),
            "per_cwe": data.get("per_cwe"),
        }
        write_json(path / "metrics.json", normalized)
        write_csv(path / "metrics.csv", rows, ["scope", "method", "tp", "fp", "tn", "fn", "precision", "recall", "f1"])
        headers = ["Method", "TP", "FP", "TN", "FN", "Precision", "Recall", "F1"]
        write_text(path / "table.md", "# " + title + "\n\n" + md_table(headers, table_rows))
        write_text(path / "table.tex", tex_table(headers, table_rows, caption=title))
        with (path / "detection_per_case.jsonl").open("w", encoding="utf-8") as handle:
            for row in data.get("rows", []):
                handle.write(json.dumps(row, sort_keys=True) + "\n")
        return normalized

    if (path / "multi_seed_summary.json").exists():
        data = read_json(path / "multi_seed_summary.json")
        rows: list[dict[str, Any]] = []
        for seed, per_method in zip(data.get("seeds", []), data.get("per_seed_overall", [])):
            for method, values in per_method.items():
                rows.append({"seed": seed, "method": method, **values})
        normalized = {"generated_at": now_iso(), "source": (path / "multi_seed_summary.json").as_posix(), **data}
        write_json(path / "metrics.json", normalized)
        write_csv(path / "metrics.csv", rows, ["seed", "method", "tp", "fp", "tn", "fn", "precision", "recall", "f1"])
        table_rows = [[r["seed"], r["method"], r["tp"], r["fp"], r["tn"], r["fn"], r["precision"], r["recall"], r["f1"]] for r in rows]
        headers = ["Seed", "Method", "TP", "FP", "TN", "FN", "Precision", "Recall", "F1"]
        write_text(path / "table.md", "# OWASP multi-seed F10 stability\n\n" + md_table(headers, table_rows))
        write_text(path / "table.tex", tex_table(headers, table_rows, caption="OWASP multi-seed F10 stability"))
        return normalized
    return {"missing": True, "path": path.as_posix()}


def normalize_f10_outputs() -> dict[str, Any]:
    dirs = [
        OUTPUTS / "lexical_noise_eval_v1",
        OUTPUTS / "lexical_noise_eval_v1_with_registry",
        OUTPUTS / "owasp_lexical_eval_v1",
        OUTPUTS / "owasp_multiseed_v1",
    ]
    return {d.name: normalize_f10_dir(d) if d.exists() else {"missing": True, "path": d.as_posix()} for d in dirs}


def policy_traceability() -> dict[str, Any]:
    catalog = {entry["id"]: entry for entry in read_json(ROOT / "policy" / "catalog.json")["controls"]}
    registry = read_json(ROOT / "configs" / "benchmark" / "policy_registry.json")
    rules = {entry["id"]: entry for entry in registry["rules"]}
    rows = []
    for category in registry["categories"]:
        for rule_id in category["rego_rule_ids"]:
            rule = rules[rule_id]
            cat_entry = catalog.get(rule_id, rule)
            reference = cat_entry.get("reference") or rule.get("reference")
            mapping_type = "direct ISO clause" if str(reference).startswith("ISO/IEC") else "pragmatic benchmark mapping"
            rows.append(
                {
                    "rule_id": rule_id,
                    "cwe": ", ".join(category.get("cwes", [])),
                    "category": category.get("label"),
                    "control_reference": reference,
                    "mapping_type": mapping_type,
                    "rego_module": cat_entry.get("rego_module"),
                    "rego_rule": cat_entry.get("rego_rule"),
                    "evidence_fields": cat_entry.get("evidence_fields", []),
                    "remediation_tier": category.get("remediation_tier"),
                }
            )
    payload = {
        "generated_at": now_iso(),
        "source_files": ["policy/catalog.json", "configs/benchmark/policy_registry.json"],
        "safe_wording": (
            "CodeGraph operationalises selected security/compliance concerns as Rego policies. The evaluated "
            "crypto/hash/randomness families use direct ISO A.10-style mappings, while the injection and path-query "
            "families are pragmatic OWASP Benchmark CWE mappings into the secure-development control area. The "
            "benchmark therefore validates pattern-level detection for those families rather than full "
            "standards-compliance fidelity."
        ),
        "rows": rows,
    }
    write_json(OUTPUTS / "policy_traceability_table_2026-05-31.json", payload)
    headers = ["Rule ID", "CWE", "Category", "Control/reference", "Mapping type", "Rego module", "Rego rule", "Evidence fields", "Remediation tier"]
    table_rows = [
        [
            r["rule_id"],
            r["cwe"],
            r["category"],
            r["control_reference"],
            r["mapping_type"],
            r["rego_module"],
            r["rego_rule"],
            ", ".join(r["evidence_fields"]),
            r["remediation_tier"],
        ]
        for r in rows
    ]
    write_text(OUTPUTS / "policy_traceability_table_2026-05-31.md", md_table(headers, table_rows) + "\n" + payload["safe_wording"] + "\n")
    write_text(OUTPUTS / "policy_traceability_table_2026-05-31.tex", tex_table(headers, table_rows, caption="Policy traceability for evaluated OWASP Benchmark families"))
    return payload


def faiss_audit() -> dict[str, Any]:
    payload = {
        "generated_at": now_iso(),
        "findings": {
            "vector_context_used_by_rego": False,
            "faiss_affects_detection": False,
            "faiss_used_for_explanation_prompt_context": True,
            "faiss_used_for_remediation_prompt_context": True,
            "ablation_artifact_exists": False,
        },
        "evidence": [
            "codegraph/policy/runtime/bundles.py builds vector_context from HybridSearchService before bundle serialization.",
            "policy/*.rego contains no vector_context references.",
            "codegraph/llm/tasks/explanation.py includes vector_context only in full evidence mode and not in lean mode.",
            "codegraph/llm/tasks/remediation.py includes vector_context in LLM-facing prompt sections when present.",
        ],
        "safe_wording": (
            "FAISS/vector search is used as evidence enrichment for LLM-facing explanation and remediation prompts. "
            "It is not part of the Rego detection decision path in the reported benchmark evaluation, and this thesis "
            "does not claim a separate detection improvement from FAISS."
        ),
    }
    lines = [
        "# FAISS Role Audit",
        "",
        payload["safe_wording"],
        "",
        "| Question | Answer |",
        "|---|---|",
    ]
    for key, value in payload["findings"].items():
        lines.append(f"| {key} | {value} |")
    lines.extend(["", "## Source Evidence", ""])
    lines.extend(f"- {item}" for item in payload["evidence"])
    write_text(OUTPUTS / "faiss_role_audit_2026-05-31.md", "\n".join(lines) + "\n")
    return payload


def metric_close(actual: float | None, expected: float, tol: float = 0.0005) -> bool:
    return actual is not None and math.isclose(float(actual), expected, abs_tol=tol)


def f10_match_notes(f10: dict[str, Any]) -> dict[str, Any]:
    notes: dict[str, Any] = {}
    lexical = f10.get("lexical_noise_eval_v1", {})
    if not lexical.get("missing"):
        m = lexical.get("metrics", {})
        notes["lexical_matches_expected"] = (
            m.get("pre_f10", {}).get("tp") == 3
            and m.get("pre_f10", {}).get("fp") == 15
            and m.get("post_f10", {}).get("fp") == 7
            and m.get("semgrep", {}).get("tp") == 5
        )
        notes["lexical_metrics"] = m
        notes["lexical_paired"] = lexical.get("paired")
    owasp = f10.get("owasp_lexical_eval_v1", {})
    if not owasp.get("missing"):
        notes["owasp_overall"] = owasp.get("metrics")
        notes["owasp_zero_delta"] = all(
            p.get("mcnemar", {}).get("b") == 0 and p.get("mcnemar", {}).get("c") == 0
            for p in owasp.get("paired", [])
        )
    return notes


def rounded_metric_row(values: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "tp": values.get("tp"),
        "fp": values.get("fp"),
        "tn": values.get("tn"),
        "fn": values.get("fn"),
        "precision": round(float(values.get("precision", 0.0)), 3),
        "recall": round(float(values.get("recall", 0.0)), 3),
        "f1": round(float(values.get("f1", 0.0)), 3),
    }


def f10_reproduction_comparison(f10: dict[str, Any]) -> dict[str, Any]:
    lexical = f10.get("lexical_noise_eval_v1", {})
    owasp = f10.get("owasp_lexical_eval_v1", {})
    lexical_pair = next(
        (
            pair
            for pair in lexical.get("paired", [])
            if pair.get("scope") == "overall"
            and pair.get("method_a") == "pre_f10"
            and pair.get("method_b") == "post_f10"
        ),
        {},
    )
    delta_fpr = lexical_pair.get("delta_fpr") or {}
    mcnemar = lexical_pair.get("mcnemar") or {}
    lexical_metrics = lexical.get("metrics", {})
    owasp_metrics = owasp.get("metrics", {})
    owasp_zero_delta = all(
        pair.get("mcnemar", {}).get("b") == 0 and pair.get("mcnemar", {}).get("c") == 0
        for pair in owasp.get("paired", [])
    )
    payload = {
        "generated_at": now_iso(),
        "lexical_noise_java": {
            "expected": {
                "pre_f10": {"tp": 3, "fp": 15, "tn": 10, "fn": 2, "precision": 0.167, "recall": 0.600, "f1": 0.261},
                "post_f10": {"tp": 3, "fp": 7, "tn": 18, "fn": 2, "precision": 0.300, "recall": 0.600, "f1": 0.400},
                "semgrep": {"tp": 5, "fp": 0, "tn": 25, "fn": 0, "precision": 1.000, "recall": 1.000, "f1": 1.000},
                "mcnemar_p": 0.0078,
                "delta_fpr": -0.320,
                "delta_fpr_ci": [-0.478, -0.154],
            },
            "actual": {
                "pre_f10": rounded_metric_row(lexical_metrics.get("pre_f10", {})),
                "post_f10": rounded_metric_row(lexical_metrics.get("post_f10", {})),
                "semgrep": rounded_metric_row(lexical_metrics.get("semgrep", {})),
                "mcnemar_p": mcnemar.get("p_value"),
                "delta_fpr": delta_fpr.get("point"),
                "delta_fpr_ci": [delta_fpr.get("ci_low"), delta_fpr.get("ci_high")],
            },
        },
        "owasp_file_level": {
            "expected": {
                "pre_f10": {"tp": 185, "fp": 24, "tn": 155, "fn": 21, "precision": 0.885, "recall": 0.898, "f1": 0.892},
                "post_f10": {"tp": 185, "fp": 24, "tn": 155, "fn": 21, "precision": 0.885, "recall": 0.898, "f1": 0.892},
                "zero_per_case_deltas": True,
            },
            "actual": {
                "pre_f10": rounded_metric_row(owasp_metrics.get("pre_f10", {})),
                "post_f10": rounded_metric_row(owasp_metrics.get("post_f10", {})),
                "zero_per_case_deltas": owasp_zero_delta,
            },
        },
        "thesis_action": (
            "Keep the LexicalNoiseJava and OWASP point metrics. Replace the LexicalNoiseJava 95% CI if citing the "
            "regenerated artifact: delta FPR CI is [-0.500, -0.154] with seed 42 and 2000 bootstrap resamples, not "
            "[-0.478, -0.154]."
        ),
    }
    expected_ci = payload["lexical_noise_java"]["expected"]["delta_fpr_ci"]
    actual_ci = payload["lexical_noise_java"]["actual"]["delta_fpr_ci"]
    payload["lexical_noise_java"]["matches_expected_delta_fpr_ci"] = all(
        metric_close(actual, expected, tol=0.0005) for actual, expected in zip(actual_ci, expected_ci, strict=True)
    )
    write_json(OUTPUTS / "f10_reproduction_comparison_2026-05-31.json", payload)
    lines = [
        "# F10 Reproduction Comparison",
        "",
        payload["thesis_action"],
        "",
        "## LexicalNoiseJava",
        "",
        md_table(
            ["Method", "TP", "FP", "TN", "FN", "P", "R", "F1"],
            [
                [
                    method,
                    row["tp"],
                    row["fp"],
                    row["tn"],
                    row["fn"],
                    row["precision"],
                    row["recall"],
                    row["f1"],
                ]
                for method, row in payload["lexical_noise_java"]["actual"].items()
                if isinstance(row, dict)
            ],
        ),
        f"- McNemar p: {payload['lexical_noise_java']['actual']['mcnemar_p']}",
        f"- Delta FPR: {payload['lexical_noise_java']['actual']['delta_fpr']}",
        f"- Delta FPR 95% CI: {payload['lexical_noise_java']['actual']['delta_fpr_ci']}",
        "",
        "## OWASP File Level",
        "",
        md_table(
            ["Method", "TP", "FP", "TN", "FN", "P", "R", "F1"],
            [
                [
                    method,
                    row["tp"],
                    row["fp"],
                    row["tn"],
                    row["fn"],
                    row["precision"],
                    row["recall"],
                    row["f1"],
                ]
                for method, row in payload["owasp_file_level"]["actual"].items()
                if isinstance(row, dict)
            ],
        ),
        f"- Zero per-case deltas: {payload['owasp_file_level']['actual']['zero_per_case_deltas']}",
    ]
    write_text(OUTPUTS / "f10_reproduction_comparison_2026-05-31.md", "\n".join(lines) + "\n")
    return payload


def build_manifest(
    detection: dict[str, Any],
    explanation: dict[str, Any],
    remediation: dict[str, Any],
    f10: dict[str, Any],
    policy: dict[str, Any],
    faiss: dict[str, Any],
) -> list[dict[str, Any]]:
    comment_path = OUTPUTS / "owasp_comment_token_scan_v1" / "summary.json"
    comment = read_json(comment_path) if comment_path.exists() else None
    pr_rem = remediation["runs"]["pr_full_verification_2026_05_11"]
    v2_rem = remediation["runs"]["v2"]
    lexical = f10.get("lexical_noise_eval_v1", {})
    owasp = f10.get("owasp_lexical_eval_v1", {})
    multiseed = f10.get("owasp_multiseed_v1", {})
    f10_comparison_path = OUTPUTS / "f10_reproduction_comparison_2026-05-31.json"
    f10_comparison = read_json(f10_comparison_path) if f10_comparison_path.exists() else {}
    objects = [
        {
            "claim_id": "detection_headline",
            "claim_text_safe_for_thesis": "On the selected 454-case OWASP eight-CWE sample, Overall detection is TP=222, FP=11, TN=210, FN=11, P/R/F1=0.9528 under union any-rule semantics.",
            "canonical_artifacts": ["outputs/thesis_final_detection_full_v2/metrics.json", "outputs/thesis_final_detection_full_v2/table_with_semantics.md"],
            "status": "confirmed",
            "metrics": detection["overall"] | {"category_row_sums": detection["category_row_sums"], "violation_count": detection["violation_count"]},
            "provenance": detection["provenance"],
            "thesis_wording_action": "narrow",
            "notes": "Overall is recomputed over selected testcase union and is not the arithmetic sum of category rows.",
        },
        {
            "claim_id": "detection_sample_basis",
            "claim_text_safe_for_thesis": "The detection set is a seed-7 capped sample: up to 60 cases per family, 454 selected from 2092 available across the eight evaluated CWE families.",
            "canonical_artifacts": ["outputs/thesis_final_detection_full_v2/selection_summary.json"],
            "status": "confirmed",
            "metrics": detection["selection"],
            "provenance": detection["provenance"],
            "thesis_wording_action": "narrow",
            "notes": "Directory name _full means full configured eight-family sample, not all available cases.",
        },
        {
            "claim_id": "explanation_citation_attribution",
            "claim_text_safe_for_thesis": explanation["safe_wording"],
            "canonical_artifacts": ["outputs/pr_full_verification_2026-05-11/explanation_full/citation_metrics.json", "outputs/pr_full_verification_2026-05-11/explanation_full/explanation_summary_for_thesis.json"],
            "status": "confirmed",
            "metrics": explanation["metrics"],
            "provenance": explanation["provenance"],
            "thesis_wording_action": "replace",
            "notes": "This evaluates citation-style attribution, not semantic faithfulness.",
        },
        {
            "claim_id": "remediation_v2_25_of_25_metric_artifact",
            "claim_text_safe_for_thesis": "The 25/25 remediation result is supported by metric artifacts but lacks exact-run provenance/model attribution.",
            "canonical_artifacts": ["outputs/thesis_final_remediation_v2/remediation_metrics.json", "outputs/thesis_final_remediation_v2/confidence_calibration.json"],
            "status": "confirmed_without_provenance",
            "metrics": {k: v2_rem.get(k) for k in ("attempted", "fix_success", "structured_valid", "replacement_applied", "policy_pass_count", "build_attempted", "build_success", "fix_success_rate", "confidence_calibration")},
            "provenance": v2_rem["provenance"],
            "thesis_wording_action": "narrow",
            "notes": "summary.md Brier/ECE is stale if STALE_SUMMARY_DO_NOT_CITE.md exists.",
        },
        {
            "claim_id": "remediation_provenance_backed_rerun",
            "claim_text_safe_for_thesis": "The provenance-backed supported-medium remediation rerun is the defensible reproducibility check.",
            "canonical_artifacts": ["outputs/pr_full_verification_2026-05-11/remediation_supported_medium/remediation_metrics.json", "outputs/remediation_canonicality_report_2026-05-31.json"],
            "status": "confirmed",
            "metrics": {k: pr_rem.get(k) for k in ("attempted", "fix_success", "structured_valid", "replacement_applied", "policy_pass_count", "build_attempted", "build_success", "fix_success_rate", "confidence_calibration")},
            "provenance": pr_rem["provenance"],
            "thesis_wording_action": "replace",
            "notes": "Use this as reproducibility evidence unless a new run is completed and chosen.",
        },
        {
            "claim_id": "f10_lexical_noise_java",
            "claim_text_safe_for_thesis": "LexicalNoiseJava F10 results are cited from regenerated machine-readable artifacts.",
            "canonical_artifacts": ["outputs/lexical_noise_eval_v1/metrics.json", "outputs/lexical_noise_eval_v1/provenance.json", "outputs/f10_reproduction_comparison_2026-05-31.json"],
            "status": "missing" if lexical.get("missing") else "reproduced",
            "metrics": lexical.get("metrics", {}),
            "provenance": provenance_summary(OUTPUTS / "lexical_noise_eval_v1" / "provenance.json"),
            "thesis_wording_action": "replace" if not f10_comparison.get("lexical_noise_java", {}).get("matches_expected_delta_fpr_ci", True) else ("keep" if not lexical.get("missing") else "delete"),
            "notes": f10_comparison.get("thesis_action") or json.dumps(f10_match_notes(f10).get("lexical_matches_expected")),
        },
        {
            "claim_id": "f10_owasp_lexical_regression",
            "claim_text_safe_for_thesis": "OWASP file-level F10 regression results are cited from regenerated machine-readable artifacts.",
            "canonical_artifacts": ["outputs/owasp_lexical_eval_v1/metrics.json", "outputs/owasp_lexical_eval_v1/provenance.json"],
            "status": "missing" if owasp.get("missing") else "reproduced",
            "metrics": owasp.get("metrics", {}),
            "provenance": provenance_summary(OUTPUTS / "owasp_lexical_eval_v1" / "provenance.json"),
            "thesis_wording_action": "keep" if not owasp.get("missing") else "delete",
            "notes": "Expected thesis values must be checked against this artifact.",
        },
        {
            "claim_id": "f10_owasp_multi_seed_stability",
            "claim_text_safe_for_thesis": "OWASP multi-seed stability is cited from regenerated machine-readable artifacts for seeds 7,13,23,42,101.",
            "canonical_artifacts": ["outputs/owasp_multiseed_v1/metrics.json", "outputs/owasp_multiseed_v1/provenance.json"],
            "status": "missing" if multiseed.get("missing") else "reproduced",
            "metrics": {"seeds": multiseed.get("seeds"), "across_seed": multiseed.get("across_seed")},
            "provenance": provenance_summary(OUTPUTS / "owasp_multiseed_v1" / "provenance.json"),
            "thesis_wording_action": "keep" if not multiseed.get("missing") else "delete",
            "notes": "Uses limit_per_cwe from the multiseed artifact.",
        },
        {
            "claim_id": "owasp_comment_token_absence_scan",
            "claim_text_safe_for_thesis": "Comment-token absence is supported only if the full-corpus scan reports zero comment occurrences for the configured trigger tokens.",
            "canonical_artifacts": ["outputs/owasp_comment_token_scan_v1/summary.json", "outputs/owasp_comment_token_scan_v1/provenance.json"],
            "status": "missing" if comment is None else ("reproduced" if comment.get("total_comment_occurrences") == 0 else "contradicted"),
            "metrics": comment or {},
            "provenance": provenance_summary(OUTPUTS / "owasp_comment_token_scan_v1" / "provenance.json"),
            "thesis_wording_action": "keep" if comment and comment.get("total_comment_occurrences") == 0 else "replace",
            "notes": "Expected total Java cases is 2740.",
        },
        {
            "claim_id": "norm_to_policy_mapping",
            "claim_text_safe_for_thesis": policy["safe_wording"],
            "canonical_artifacts": ["outputs/policy_traceability_table_2026-05-31.json"],
            "status": "confirmed",
            "metrics": {
                "direct_iso_clause": sum(1 for r in policy["rows"] if r["mapping_type"] == "direct ISO clause"),
                "pragmatic_benchmark_mapping": sum(1 for r in policy["rows"] if r["mapping_type"] == "pragmatic benchmark mapping"),
            },
            "provenance": {"exists": False, "path": None, "git_sha": git_sha(), "seed": None, "model": None, "config": "policy/catalog.json + configs/benchmark/policy_registry.json"},
            "thesis_wording_action": "narrow",
            "notes": "The evaluated injection/path families are pragmatic benchmark mappings, not direct ISO clauses.",
        },
        {
            "claim_id": "faiss_role",
            "claim_text_safe_for_thesis": faiss["safe_wording"],
            "canonical_artifacts": ["outputs/faiss_role_audit_2026-05-31.md"],
            "status": "confirmed",
            "metrics": faiss["findings"],
            "provenance": {"exists": False, "path": None, "git_sha": git_sha(), "seed": None, "model": None, "config": "source audit"},
            "thesis_wording_action": "narrow",
            "notes": "No FAISS-off detection ablation artifact exists.",
        },
    ]
    return objects


def write_manifest(manifest: list[dict[str, Any]]) -> None:
    json_path = OUTPUTS / "thesis_evidence_manifest_2026-05-31.json"
    md_path = OUTPUTS / "thesis_evidence_manifest_2026-05-31.md"
    write_json(json_path, manifest)
    headers = ["Claim", "Status", "Artifacts", "Action", "Notes"]
    rows = [
        [
            item["claim_id"],
            item["status"],
            "<br>".join(item["canonical_artifacts"]),
            item["thesis_wording_action"],
            item["notes"],
        ]
        for item in manifest
    ]
    write_text(md_path, "# Thesis Evidence Manifest (2026-05-31)\n\n" + md_table(headers, rows))


def main() -> int:
    detection = detection_artifacts()
    explanation = explanation_artifacts()
    remediation = remediation_report()
    mark_v2_summary_stale_if_needed(remediation)
    f10 = normalize_f10_outputs()
    f10_reproduction_comparison(f10)
    policy = policy_traceability()
    faiss = faiss_audit()
    write_manifest(build_manifest(detection, explanation, remediation, f10, policy, faiss))
    print("wrote thesis evidence artifacts")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
