#!/usr/bin/env python3
"""Export the final merged agentic remediation benchmark artifact."""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from codegraph.evaluation.io import write_json  # noqa: E402
from codegraph.evaluation.provenance import collect_provenance, write_provenance  # noqa: E402
from codegraph.evaluation.remediation_runtime_helpers import build_agentic_outcome_summary  # noqa: E402


def main() -> int:
    source_dir = REPO_ROOT / "outputs" / "agentic_baseline_100_final_v3"
    target_dir = REPO_ROOT / "outputs" / "2026-09-22-agentic-remediation-final"
    target_dir.mkdir(parents=True, exist_ok=True)

    with open(source_dir / "results.json", encoding="utf-8") as f:
        cases = json.load(f)

    outcomes = build_agentic_outcome_summary(cases)
    write_json(target_dir / "agentic_outcomes.json", outcomes)
    write_json(target_dir / "results.json", cases)

    with open(target_dir / "results.jsonl", "w", encoding="utf-8") as f:
        for c in cases:
            f.write(json.dumps(c) + "\n")

    prov = collect_provenance(
        output_dir="outputs/2026-09-22-agentic-remediation-final",
        config_path="configs/benchmark/remediation_retry_failed.json",
        eval_kind="agentic_remediation",
        seed=42,
        extra={
            "total_cases": len(cases),
            "mode": "agentic",
            "model": "qwen/qwen3.8-27b",
            "llm_api_base": "http://127.0.0.1:1234/v1",
            "correct_outcome_rate": outcomes["correct_outcome_rate"],
        },
    )
    write_provenance(prov, target_dir)

    total = len(cases)
    correct_fix = outcomes["correct_fix"]
    correct_abstain = outcomes["correct_abstain"]
    false_fix = outcomes["false_fix"]
    missed_fix = outcomes["missed_fix"]
    inconclusive = outcomes["inconclusive_error_or_timeout"]
    rate = outcomes["correct_outcome_rate"]

    categories: dict[str, dict[str, int]] = {}
    for c in cases:
        cat = c.get("category") or "Unknown"
        if cat not in categories:
            categories[cat] = {"total": 0, "tp": 0, "fp": 0, "success": 0, "refused": 0, "timeout": 0, "build_pass": 0}
        categories[cat]["total"] += 1
        if c.get("ground_truth_label") is True:
            categories[cat]["tp"] += 1
        else:
            categories[cat]["fp"] += 1
        if c.get("status") == "SUCCESS":
            categories[cat]["success"] += 1
        elif c.get("status") == "REFUSED":
            categories[cat]["refused"] += 1
        else:
            categories[cat]["timeout"] += 1
        if c.get("build_pass") is True or c.get("compilation", {}).get("success") is True:
            categories[cat]["build_pass"] += 1

    summary_lines = [
        "# Agentic Remediation Evaluation - Final Merged Baseline",
        "",
        "- **Artifact Directory**: `outputs/2026-09-22-agentic-remediation-final/`",
        f"- **Commit**: `{prov.get('git', {}).get('sha', 'ba77516')}`",
        "- **Model**: `qwen/qwen3.8-27b` (local MLX / LM Studio)",
        "- **Evaluation Mode**: `agentic` (3-gate verification: JDT compilation, regression tests, policy recheck)",
        f"- **Total Evaluated Cases**: `{total}`",
        f"- **Correct Outcome Rate**: `{rate * 100:.2f}%` ({correct_fix + correct_abstain} / {total})",
        "",
        "## Headline Outcome Breakdown",
        "",
        "| Outcome Classification | Count | Percentage | Description |",
        "| :--- | :--- | :--- | :--- |",
        f"| **Fixed Vulnerabilities (Correct Fix)** | `{correct_fix}` | `{correct_fix / total * 100:.1f}%` | True positive vulnerability correctly remediated and passed 3 gates |",
        f"| **Correct Abstentions** | `{correct_abstain}` | `{correct_abstain / total * 100:.1f}%` | Benign testcase (false finding) where agent correctly refused remediation |",
        f"| **False Fixes** | `{false_fix}` | `{false_fix / total * 100:.1f}%` | Benign testcase where remediation was applied despite no real vulnerability |",
        f"| **Missed Fixes** | `{missed_fix}` | `{missed_fix / total * 100:.1f}%` | True vulnerability where agent incorrectly refused remediation |",
        f"| **Inconclusive / Timeout / Max Turns** | `{inconclusive}` | `{inconclusive / total * 100:.1f}%` | Agent exceeded maximum allowed turns or encountered scoped config barrier |",
        "",
        "## Category Breakdown",
        "",
        "| Category | Total Cases | True Positives | Benign (FP) | 3-Gate Success | Refused | Max Turns / Inconclusive | Build Pass Rate |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ]

    for cat, d in sorted(categories.items()):
        build_rate = (d["build_pass"] / d["total"]) * 100
        summary_lines.append(
            f"| {cat} | {d['total']} | {d['tp']} | {d['fp']} | {d['success']} | {d['refused']} | {d['timeout']} | {build_rate:.1f}% ({d['build_pass']}/{d['total']}) |"
        )

    summary_md = "\n".join(summary_lines) + "\n"
    (target_dir / "summary.md").write_text(summary_md, encoding="utf-8")

    table_lines = [
        "| Metric | Value |",
        "| --- | --- |",
        f"| Total Cases | {total} |",
        f"| Correct Outcome Rate | {rate:.4f} |",
        f"| Correct Fixes | {correct_fix} |",
        f"| Correct Abstentions | {correct_abstain} |",
        f"| False Fixes | {false_fix} |",
        f"| Missed Fixes | {missed_fix} |",
        f"| Inconclusive / Max Turns | {inconclusive} |",
    ]
    (target_dir / "table.md").write_text("\n".join(table_lines) + "\n", encoding="utf-8")

    with open(target_dir / "remediation_metrics.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["category", "total", "tp", "fp", "success", "refused", "inconclusive", "build_pass"])
        for cat, d in sorted(categories.items()):
            writer.writerow([cat, d["total"], d["tp"], d["fp"], d["success"], d["refused"], d["timeout"], d["build_pass"]])

    print("Successfully exported artifact to:", target_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
