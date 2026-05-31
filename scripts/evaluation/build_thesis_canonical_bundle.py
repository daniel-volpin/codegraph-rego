"""Build the canonical thesis evidence bundle from existing artifacts."""

from __future__ import annotations

import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

ROOT = Path(__file__).resolve().parents[2]
OUTPUTS = ROOT / "outputs"
CANONICAL = OUTPUTS / "thesis_canonical_2026-05-31"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def git_sha() -> str:
    proc = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=False)
    return proc.stdout.strip()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def rel(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def copy_artifact(src: Path, dest_dir: Path, name: str | None = None) -> Path:
    if not src.exists():
        raise FileNotFoundError(src)
    dest = dest_dir / (name or src.name)
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dest)
    return dest


def copy_many(dest_dir: str, sources: Sequence[str]) -> list[str]:
    copied: list[str] = []
    target = CANONICAL / dest_dir
    for source in sources:
        copied.append(rel(copy_artifact(ROOT / source, target)))
    return copied


def provenance(path: Path | None) -> dict[str, Any]:
    if path is None or not path.exists():
        return {"exists": False, "path": None, "git_sha": None, "model": None, "seed": None, "config": None}
    data = read_json(path)
    llm = data.get("llm") or {}
    return {
        "exists": True,
        "path": rel(path),
        "git_sha": (data.get("git") or {}).get("sha"),
        "model": llm.get("remediation_model") or llm.get("model"),
        "seed": data.get("seed"),
        "config": (data.get("config") or {}).get("path"),
    }


def fmt(value: float | int | str | None, digits: int = 3) -> str:
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


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


def tex_table(headers: Sequence[str], rows: Iterable[Sequence[Any]], caption: str | None = None) -> str:
    lines = [r"\begin{tabular}{" + "l" * len(headers) + "}", r"\hline"]
    lines.append(" & ".join(tex_escape(h) for h in headers) + r" \\")
    lines.append(r"\hline")
    for row in rows:
        lines.append(" & ".join(tex_escape(cell) for cell in row) + r" \\")
    lines.extend([r"\hline", r"\end{tabular}"])
    if caption:
        lines.append(r"\caption{" + tex_escape(caption) + "}")
    return "\n".join(lines) + "\n"


def md_table(headers: Sequence[str], rows: Iterable[Sequence[Any]]) -> str:
    out = ["| " + " | ".join(headers) + " |", "| " + " | ".join(["---"] * len(headers)) + " |"]
    out.extend("| " + " | ".join(str(cell) for cell in row) + " |" for row in rows)
    return "\n".join(out) + "\n"


def metric_subset(values: Mapping[str, Any], keys: Sequence[str]) -> dict[str, Any]:
    return {key: values.get(key) for key in keys}


def build_nonreproducible_note() -> None:
    v2 = read_json(OUTPUTS / "thesis_final_remediation_v2" / "remediation_metrics.json")
    case_ids = [row.get("case_id") for row in v2.get("results", [])]
    lines = [
        "# Remediation v2 25/25 Reproduction Status",
        "",
        "Exact v2 reproduction is not recoverable from machine-readable artifacts in this repository.",
        "",
        "## Recoverable",
        "",
        f"- Historical generated_at: `{v2.get('generated_at')}`",
        f"- Config family from metrics: `{v2.get('selection', {}).get('categories')}`",
        f"- Selection seed from metrics: `{v2.get('selection', {}).get('seed')}`",
        f"- Max cases per category from metrics: `{v2.get('selection', {}).get('max_cases_per_category')}`",
        f"- Attempted count: `{v2.get('attempted')}`",
        f"- Historical success count: `{v2.get('fix_success')}`",
        f"- Case ids: `{', '.join(case_ids)}`",
        "",
        "## Missing",
        "",
        "- No `provenance.json` exists for `outputs/thesis_final_remediation_v2/`.",
        "- The exact remediation model/provider is not recorded in the v2 JSON artifacts.",
        "- Prompt/schema version, temperature, and environment/provider settings are not recorded in v2 JSON artifacts.",
        "- Markdown prose references Qwen settings, but prose is not sufficient provenance for the thesis evidence rules.",
        "",
        "## Attempted command",
        "",
        "No command was run for exact v2 reproduction because the exact settings are not recoverable. "
        "A guessed rerun would create a new result, not provenance for the historical 25/25 claim.",
        "",
        "## Thesis-safe conclusion",
        "",
        "The v2 25/25 result remains historical metric evidence only. Use the provenance-backed PR verification "
        "run as the defensible remediation reproducibility check unless a future exact-provenance rerun is produced.",
    ]
    write_text(OUTPUTS / "thesis_final_remediation_v2_repro_2026-05-31" / "FAILED_OR_NONREPRODUCIBLE.md", "\n".join(lines) + "\n")


def build_no_retry_note() -> None:
    lines = [
        "# Full-Population Detection Retry Status",
        "",
        "No second full-population detection retry was attempted in this commit.",
        "",
        "The previous run in this directory failed before metrics because Neo4j authentication/rate-limit state was not "
        "fixed. Retrying with the same unknown credentials would not strengthen the evidence and could further rate-limit "
        "the local Neo4j instance.",
        "",
        "Thesis-safe conclusion: keep the 454-case selected-sample detection claim unless a future environment-fixed "
        "full-population run completes and writes metrics/provenance.",
    ]
    write_text(OUTPUTS / "thesis_full_population_detection_2026-05-31" / "NO_RETRY_ENV_NOT_FIXED.md", "\n".join(lines) + "\n")


def build_manifest() -> dict[str, Any]:
    CANONICAL.mkdir(parents=True, exist_ok=True)
    detection_files = copy_many(
        "detection",
        [
            "outputs/thesis_final_detection_full_v2/metrics.json",
            "outputs/thesis_final_detection_full_v2/metrics.csv",
            "outputs/thesis_final_detection_full_v2/provenance.json",
            "outputs/thesis_final_detection_full_v2/selection_summary.json",
            "outputs/thesis_final_detection_full_v2/table_with_semantics.md",
            "outputs/thesis_final_detection_full_v2/table_with_semantics.tex",
        ],
    )
    explanation_files = copy_many(
        "explanation",
        [
            "outputs/pr_full_verification_2026-05-11/explanation_full/citation_metrics.json",
            "outputs/pr_full_verification_2026-05-11/explanation_full/citation_metrics.csv",
            "outputs/pr_full_verification_2026-05-11/explanation_full/provenance.json",
            "outputs/pr_full_verification_2026-05-11/explanation_full/table.md",
            "outputs/pr_full_verification_2026-05-11/explanation_full/table.tex",
            "outputs/pr_full_verification_2026-05-11/explanation_full/explanation_summary_for_thesis.json",
        ],
    )
    remediation_files = copy_many(
        "remediation",
        [
            "outputs/thesis_final_remediation_v2/STALE_SUMMARY_DO_NOT_CITE.md",
            "outputs/pr_full_verification_2026-05-11/remediation_supported_medium/provenance.json",
            "outputs/remediation_canonicality_report_2026-05-31.json",
            "outputs/remediation_canonicality_report_2026-05-31.md",
            "outputs/thesis_final_remediation_v2_repro_2026-05-31/FAILED_OR_NONREPRODUCIBLE.md",
            "outputs/thesis_final_remediation_repro_2026-05-31/FAILED_RUN.md",
        ],
    )
    lexical_files = copy_many(
        "f10_lexical_noise",
        [
            "outputs/lexical_noise_eval_v1/metrics.json",
            "outputs/lexical_noise_eval_v1/metrics.csv",
            "outputs/lexical_noise_eval_v1/provenance.json",
            "outputs/lexical_noise_eval_v1/detection_per_case.jsonl",
            "outputs/lexical_noise_eval_v1/table.md",
            "outputs/lexical_noise_eval_v1/table.tex",
            "outputs/f10_reproduction_comparison_2026-05-31.json",
            "outputs/f10_reproduction_comparison_2026-05-31.md",
        ],
    )
    owasp_files = copy_many(
        "f10_owasp_regression",
        [
            "outputs/owasp_lexical_eval_v1/metrics.json",
            "outputs/owasp_lexical_eval_v1/metrics.csv",
            "outputs/owasp_lexical_eval_v1/provenance.json",
            "outputs/owasp_lexical_eval_v1/detection_per_case.jsonl",
            "outputs/owasp_lexical_eval_v1/table.md",
            "outputs/owasp_lexical_eval_v1/table.tex",
        ],
    )
    multiseed_files = copy_many(
        "f10_multiseed",
        [
            "outputs/owasp_multiseed_v1/metrics.json",
            "outputs/owasp_multiseed_v1/metrics.csv",
            "outputs/owasp_multiseed_v1/provenance.json",
            "outputs/owasp_multiseed_v1/multi_seed_summary.json",
            "outputs/owasp_multiseed_v1/multi_seed_summary.md",
            "outputs/owasp_multiseed_v1/table.md",
            "outputs/owasp_multiseed_v1/table.tex",
        ],
    )
    comment_files = copy_many(
        "f10_comment_scan",
        ["outputs/owasp_comment_token_scan_v1/summary.json", "outputs/owasp_comment_token_scan_v1/provenance.json"],
    )
    policy_files = copy_many(
        "policy_traceability",
        [
            "outputs/policy_traceability_table_2026-05-31.json",
            "outputs/policy_traceability_table_2026-05-31.md",
            "outputs/policy_traceability_table_2026-05-31.tex",
        ],
    )
    faiss_files = copy_many("faiss_role", ["outputs/faiss_role_audit_2026-05-31.md"])

    detection = read_json(CANONICAL / "detection" / "metrics.json")
    detection_selection = read_json(CANONICAL / "detection" / "selection_summary.json")
    explanation = read_json(CANONICAL / "explanation" / "citation_metrics.json")
    copy_artifact(
        OUTPUTS / "pr_full_verification_2026-05-11/remediation_supported_medium/remediation_metrics.json",
        CANONICAL / "remediation",
        "pr_remediation_metrics.json",
    )
    copy_artifact(
        OUTPUTS / "pr_full_verification_2026-05-11/remediation_supported_medium/confidence_calibration.json",
        CANONICAL / "remediation",
        "pr_confidence_calibration.json",
    )
    copy_artifact(
        OUTPUTS / "thesis_final_remediation_v2/remediation_metrics.json",
        CANONICAL / "remediation",
        "v2_remediation_metrics.json",
    )
    copy_artifact(
        OUTPUTS / "thesis_final_remediation_v2/confidence_calibration.json",
        CANONICAL / "remediation",
        "v2_confidence_calibration.json",
    )
    remediation_files.extend(
        [
            rel(CANONICAL / "remediation" / "pr_remediation_metrics.json"),
            rel(CANONICAL / "remediation" / "pr_confidence_calibration.json"),
            rel(CANONICAL / "remediation" / "v2_remediation_metrics.json"),
            rel(CANONICAL / "remediation" / "v2_confidence_calibration.json"),
        ]
    )
    v2_remediation = read_json(CANONICAL / "remediation" / "v2_remediation_metrics.json")
    pr_remediation = read_json(CANONICAL / "remediation" / "pr_remediation_metrics.json")
    lexical = read_json(CANONICAL / "f10_lexical_noise" / "metrics.json")
    f10_comparison = read_json(CANONICAL / "f10_lexical_noise" / "f10_reproduction_comparison_2026-05-31.json")
    owasp = read_json(CANONICAL / "f10_owasp_regression" / "metrics.json")
    multiseed = read_json(CANONICAL / "f10_multiseed" / "metrics.json")
    comment = read_json(CANONICAL / "f10_comment_scan" / "summary.json")
    policy = read_json(CANONICAL / "policy_traceability" / "policy_traceability_table_2026-05-31.json")

    overall = detection["metrics"]["overall"]
    exp_overall = explanation["metrics"]["overall"]
    claims = [
        {
            "claim_id": "detection_headline",
            "claim_text_safe_for_thesis": "On the selected OWASP Benchmark eight-CWE evaluation set (n=454), union any-rule detection gives TP=222, FP=11, TN=210, FN=11, P/R/F1=0.9528.",
            "canonical_artifacts": detection_files,
            "metrics": metric_subset(overall, ["tp", "fp", "tn", "fn", "precision", "recall", "f1", "support"])
            | {
                "category_row_sums": {"tp": 222, "fp": 9, "tn": 212, "fn": 11},
                "violation_count": detection.get("violation_count"),
                "semantics": "union_any_rule_over_selected_testcase_union",
            },
            "provenance": provenance(CANONICAL / "detection" / "provenance.json"),
            "status": "fully_provenance_backed",
            "thesis_wording_action": "narrow",
        },
        {
            "claim_id": "detection_sample_basis",
            "claim_text_safe_for_thesis": "The detection result is a seed-7 capped sample: 454 selected cases from 2092 available cases, with max_cases_per_category=60.",
            "canonical_artifacts": [rel(CANONICAL / "detection" / "selection_summary.json")],
            "metrics": detection_selection,
            "provenance": provenance(CANONICAL / "detection" / "provenance.json"),
            "status": "fully_provenance_backed",
            "thesis_wording_action": "narrow",
        },
        {
            "claim_id": "explanation_citation_attribution",
            "claim_text_safe_for_thesis": "Explanation evaluation measures citation-style attribution in structured explanations: TP context 222/222, TP no-context 0/222, FP context 9/9, FP no-context 0/9.",
            "canonical_artifacts": explanation_files,
            "metrics": {
                "tp": exp_overall["tp"],
                "fp": exp_overall["fp"],
            },
            "provenance": provenance(CANONICAL / "explanation" / "provenance.json"),
            "status": "fully_provenance_backed",
            "thesis_wording_action": "replace",
        },
        {
            "claim_id": "remediation_v2_historical_25_of_25",
            "claim_text_safe_for_thesis": "The v2 25/25 remediation result is historical metric evidence only; exact-run provenance/model attribution is absent.",
            "canonical_artifacts": [
                rel(CANONICAL / "remediation" / "v2_remediation_metrics.json"),
                rel(CANONICAL / "remediation" / "v2_confidence_calibration.json"),
                rel(CANONICAL / "remediation" / "FAILED_OR_NONREPRODUCIBLE.md"),
            ],
            "metrics": metric_subset(
                v2_remediation,
                [
                    "attempted",
                    "fix_success",
                    "structured_valid",
                    "replacement_applied",
                    "policy_pass_count",
                    "build_attempted",
                    "build_success",
                    "fix_success_rate",
                    "confidence_calibration",
                ],
            ),
            "provenance": {"exists": False, "path": None, "git_sha": None, "model": None, "seed": 42, "config": "configs/benchmark/remediation_supported_medium.json"},
            "status": "metric_backed_no_provenance",
            "thesis_wording_action": "narrow",
        },
        {
            "claim_id": "remediation_pr_reproducibility_19_of_25",
            "claim_text_safe_for_thesis": "The provenance-backed supported-medium remediation reproducibility run fully verified 19/25 cases.",
            "canonical_artifacts": [
                rel(CANONICAL / "remediation" / "pr_remediation_metrics.json"),
                rel(CANONICAL / "remediation" / "pr_confidence_calibration.json"),
                rel(CANONICAL / "remediation" / "provenance.json"),
            ],
            "metrics": metric_subset(
                pr_remediation,
                [
                    "attempted",
                    "fix_success",
                    "structured_valid",
                    "replacement_applied",
                    "policy_pass_count",
                    "build_attempted",
                    "build_success",
                    "fix_success_rate",
                    "confidence_calibration",
                ],
            ),
            "provenance": provenance(CANONICAL / "remediation" / "provenance.json"),
            "status": "fully_provenance_backed",
            "thesis_wording_action": "replace",
        },
        {
            "claim_id": "f10_lexical_noise_java",
            "claim_text_safe_for_thesis": "LexicalNoiseJava point metrics reproduce; regenerated Delta FPR 95% CI is [-0.500, -0.154].",
            "canonical_artifacts": lexical_files,
            "metrics": {
                "metrics": lexical["metrics"],
                "delta_fpr_ci": f10_comparison["lexical_noise_java"]["actual"]["delta_fpr_ci"],
            },
            "provenance": provenance(CANONICAL / "f10_lexical_noise" / "provenance.json"),
            "status": "fully_provenance_backed",
            "thesis_wording_action": "replace",
        },
        {
            "claim_id": "f10_owasp_regression",
            "claim_text_safe_for_thesis": "OWASP file-level pre/post F10 metrics are unchanged and have zero per-case deltas.",
            "canonical_artifacts": owasp_files,
            "metrics": {"metrics": owasp["metrics"], "paired_zero_deltas": True},
            "provenance": provenance(CANONICAL / "f10_owasp_regression" / "provenance.json"),
            "status": "fully_provenance_backed",
            "thesis_wording_action": "keep",
        },
        {
            "claim_id": "f10_multiseed",
            "claim_text_safe_for_thesis": "OWASP multi-seed F10 stability is backed for seeds 7,13,23,42,101 at limit_per_cwe=50.",
            "canonical_artifacts": multiseed_files,
            "metrics": {"seeds": multiseed.get("seeds"), "across_seed": multiseed.get("across_seed")},
            "provenance": provenance(CANONICAL / "f10_multiseed" / "provenance.json"),
            "status": "fully_provenance_backed",
            "thesis_wording_action": "keep",
        },
        {
            "claim_id": "f10_comment_scan",
            "claim_text_safe_for_thesis": "The full OWASP Java corpus scan found zero comment-only occurrences for the configured lexical trigger tokens.",
            "canonical_artifacts": comment_files,
            "metrics": comment,
            "provenance": provenance(CANONICAL / "f10_comment_scan" / "provenance.json"),
            "status": "fully_provenance_backed",
            "thesis_wording_action": "keep",
        },
        {
            "claim_id": "policy_traceability",
            "claim_text_safe_for_thesis": policy["safe_wording"],
            "canonical_artifacts": policy_files,
            "metrics": {
                "direct_iso_clause": sum(1 for row in policy["rows"] if row["mapping_type"] == "direct ISO clause"),
                "pragmatic_benchmark_mapping": sum(1 for row in policy["rows"] if row["mapping_type"] == "pragmatic benchmark mapping"),
            },
            "provenance": {"exists": False, "path": None, "git_sha": git_sha(), "model": None, "seed": None, "config": "policy/catalog.json + configs/benchmark/policy_registry.json"},
            "status": "source_audit_only",
            "thesis_wording_action": "narrow",
        },
        {
            "claim_id": "faiss_role",
            "claim_text_safe_for_thesis": "FAISS/vector search is evidence enrichment for LLM-facing explanation/remediation prompts; it is not part of the Rego detection decision path.",
            "canonical_artifacts": faiss_files,
            "metrics": {"faiss_affects_detection": False, "vector_context_used_by_rego": False},
            "provenance": {"exists": False, "path": None, "git_sha": git_sha(), "model": None, "seed": None, "config": "source audit"},
            "status": "source_audit_only",
            "thesis_wording_action": "narrow",
        },
        {
            "claim_id": "full_population_detection_attempt",
            "claim_text_safe_for_thesis": "A true full-population eight-family detection run was attempted but did not produce metrics because local Neo4j authentication was not fixed.",
            "canonical_artifacts": [
                "outputs/thesis_full_population_detection_2026-05-31/FAILED_RUN.md",
                "outputs/thesis_full_population_detection_2026-05-31/NO_RETRY_ENV_NOT_FIXED.md",
            ],
            "metrics": {},
            "provenance": provenance(OUTPUTS / "thesis_full_population_detection_2026-05-31" / "provenance.json"),
            "status": "failed_run_recorded",
            "thesis_wording_action": "narrow",
        },
    ]
    return {
        "generated_at": now_iso(),
        "canonical_root": rel(CANONICAL),
        "source_git_sha": git_sha(),
        "claims": claims,
    }


def build_latex(manifest: Mapping[str, Any]) -> None:
    latex_dir = CANONICAL / "latex"
    explanation = next(item for item in manifest["claims"] if item["claim_id"] == "explanation_citation_attribution")
    rem_v2 = next(item for item in manifest["claims"] if item["claim_id"] == "remediation_v2_historical_25_of_25")
    rem_pr = next(item for item in manifest["claims"] if item["claim_id"] == "remediation_pr_reproducibility_19_of_25")
    f10 = next(item for item in manifest["claims"] if item["claim_id"] == "f10_lexical_noise_java")
    write_text(
        latex_dir / "detection_table_note.tex",
        "Detection performance on the selected OWASP Benchmark eight-CWE evaluation set (n=454). "
        "Per-CWE rows evaluate each category against its mapped Rego rule(s); the Overall row is recomputed over "
        "the selected testcase union using any evaluated rule firing as the positive prediction. Because a benign "
        "testcase selected under one CWE can fire an off-target rule from another CWE, the Overall row is not the "
        "arithmetic sum of per-CWE rows. Summing category rows gives FP=9/TN=212; the union any-rule Overall row "
        "gives FP=11/TN=210. violation_count=255 counts emitted rule violations and is not used as the "
        "confusion-matrix denominator.\n",
    )
    write_text(
        latex_dir / "detection_selection_sentence.tex",
        (
            "The detection evaluation uses a seed-7 capped sample of 454 cases from 2092 available OWASP Benchmark "
            "cases across the eight evaluated CWE families, with max_cases_per_category=60.\n"
        ),
    )
    exp_tp = explanation["metrics"]["tp"]
    exp_fp = explanation["metrics"]["fp"]
    write_text(
        latex_dir / "explanation_table.tex",
        tex_table(
            ["Cohort", "Count", "With context citations", "No-context citations"],
            [["TP", exp_tp["count"], exp_tp["with_context"], exp_tp["without_context"]], ["FP", exp_fp["count"], exp_fp["with_context"], exp_fp["without_context"]]],
            "Citation-style attribution in structured explanations",
        ),
    )
    write_text(
        latex_dir / "remediation_table_historical_and_repro.tex",
        tex_table(
            ["Run", "Fully verified", "Provenance", "Model", "Thesis use"],
            [
                ["v2 historical", f"{rem_v2['metrics']['fix_success']}/{rem_v2['metrics']['attempted']}", "No", "not recorded", "Historical metric evidence"],
                [
                    "PR verification",
                    f"{rem_pr['metrics']['fix_success']}/{rem_pr['metrics']['attempted']}",
                    "Yes",
                    rem_pr["provenance"]["model"],
                    "Canonical reproducibility check",
                ],
            ],
            "Historical and provenance-backed remediation evidence",
        ),
    )
    lexical_metrics = f10["metrics"]["metrics"]
    write_text(
        latex_dir / "f10_table_5_3_corrected.tex",
        tex_table(
            ["Method", "TP", "FP", "TN", "FN", "P", "R", "F1"],
            [
                ["pre-F10", 3, 15, 10, 2, "0.167", "0.600", "0.261"],
                ["post-F10", 3, 7, 18, 2, "0.300", "0.600", "0.400"],
                ["SemGrep", 5, 0, 25, 0, "1.000", "1.000", "1.000"],
            ],
            "LexicalNoiseJava F10 results; regenerated Delta FPR 95\\% CI is [-0.500, -0.154]",
        )
        + f"% Source methods: {', '.join(sorted(lexical_metrics))}\n",
    )
    copy_artifact(CANONICAL / "policy_traceability" / "policy_traceability_table_2026-05-31.tex", latex_dir, "policy_traceability_table.tex")
    artifact_rows = [
        [item["claim_id"], item["status"], "; ".join(item["canonical_artifacts"][:3])]
        for item in manifest["claims"]
    ]
    write_text(
        latex_dir / "appendix_artifact_list.tex",
        tex_table(["Claim", "Status", "Canonical artifacts"], artifact_rows, "Canonical thesis evidence artifacts"),
    )


def write_readmes(manifest: Mapping[str, Any]) -> None:
    rows = [
        [item["claim_id"], item["status"], item["thesis_wording_action"], "; ".join(item["canonical_artifacts"][:2])]
        for item in manifest["claims"]
    ]
    readme = [
        "# Canonical Thesis Evidence Bundle (2026-05-31)",
        "",
        "This directory contains copied, thesis-citable evidence artifacts. Prefer these paths over older output directories.",
        "",
        "## Do Not Cite Warning",
        "",
        "Do not cite stale or historical paths directly unless the relevant manifest row marks them as historical evidence. "
        "In particular, do not cite `outputs/thesis_final_remediation_v2/summary.md` for Brier/ECE, and do not cite the "
        "absent Appendix-A path `outputs/thesis_final_remediation_supported_calibrated_codex_20260428_122959/`.",
        "",
        md_table(["Claim", "Status", "Action", "Artifact examples"], rows),
    ]
    write_text(CANONICAL / "README.md", "\n".join(readme))

    artifact_rows = [
        ["outputs/thesis_canonical_2026-05-31/", "canonical", "Copied bundle for thesis citation", "n/a"],
        ["outputs/thesis_final_detection_full_v2/", "canonical", "Detection headline source with provenance and union-any-rule table semantics", "outputs/thesis_canonical_2026-05-31/detection/"],
        ["outputs/thesis_final_detection_full/", "historical", "Earlier detection run; replaced by v2 for thesis citation", "outputs/thesis_final_detection_full_v2/"],
        ["outputs/thesis_final_explanation_full/", "historical/stale", "Older explanation surface; replaced by PR verification TP/FP attribution run", "outputs/pr_full_verification_2026-05-11/explanation_full/"],
        ["outputs/pr_full_verification_2026-05-11/explanation_full/", "canonical", "Provenance-backed explanation citation-attribution evidence", "outputs/thesis_canonical_2026-05-31/explanation/"],
        ["outputs/thesis_final_remediation_v2/", "historical", "25/25 metrics exist, but exact-run provenance/model attribution is missing", "outputs/thesis_canonical_2026-05-31/remediation/"],
        ["outputs/thesis_final_remediation_v2/summary.md", "stale/do-not-cite", "Brier/ECE conflicts with JSON artifacts", "outputs/thesis_final_remediation_v2/remediation_metrics.json"],
        ["outputs/thesis_final_remediation_v3/", "historical", "Provenance-backed but weaker 18/25 run; not thesis headline unless chosen", "outputs/remediation_canonicality_report_2026-05-31.json"],
        ["outputs/pr_full_verification_2026-05-11/remediation_supported_medium/", "canonical", "19/25 provenance-backed remediation reproducibility run", "outputs/thesis_canonical_2026-05-31/remediation/"],
        ["outputs/thesis_final_remediation_supported_calibrated_codex_20260428_122959/", "do-not-cite", "Path is absent in this checkout", "outputs/thesis_canonical_2026-05-31/remediation/"],
        ["outputs/lexical_noise_eval_v1/", "canonical", "Regenerated LexicalNoiseJava F10 point metrics/provenance", "outputs/thesis_canonical_2026-05-31/f10_lexical_noise/"],
        ["outputs/owasp_lexical_eval_v1/", "canonical", "Regenerated OWASP F10 regression/provenance", "outputs/thesis_canonical_2026-05-31/f10_owasp_regression/"],
        ["outputs/owasp_multiseed_v1/", "canonical", "Regenerated OWASP F10 multiseed/provenance", "outputs/thesis_canonical_2026-05-31/f10_multiseed/"],
        ["outputs/owasp_comment_token_scan_v1/", "canonical", "Full-corpus comment-token absence scan", "outputs/thesis_canonical_2026-05-31/f10_comment_scan/"],
    ]
    write_text(
        OUTPUTS / "README_CANONICAL_ARTIFACTS.md",
        "# Canonical Artifact Index\n\n" + md_table(["Artifact path", "Status", "Reason", "Replacement path"], artifact_rows),
    )


def main() -> int:
    build_nonreproducible_note()
    build_no_retry_note()
    manifest = build_manifest()
    write_json(CANONICAL / "manifest.json", manifest)
    build_latex(manifest)
    write_readmes(manifest)
    print(f"wrote {rel(CANONICAL)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
