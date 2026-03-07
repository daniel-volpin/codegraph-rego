"""
Run remediation success evaluation using the same apply/verify flow as the API.
"""

from __future__ import annotations

import argparse
import logging
import random
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from codegraph.remediation.orchestration import apply_remediation
from codegraph.evaluation.pipeline import (
    collect_category_violations,
    group_violations_by_testcase,
    ingest_and_evaluate_subset,
    load_benchmark_evaluation_context,
    staged_benchmark_workspace,
)
from codegraph.evaluation.io import render_latex_table, render_markdown_table, write_csv, write_json

LOGGER = logging.getLogger("codegraph.eval.remediation")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run remediation success evaluation.")
    parser.add_argument(
        "--config",
        default="configs/benchmark/remediation_hash_smoke.json",
        help="Benchmark selection config JSON (default: %(default)s)",
    )
    parser.add_argument(
        "--mapping",
        default="configs/control_mapping.json",
        help="Control/CWE/Rego mapping JSON (default: %(default)s)",
    )
    parser.add_argument(
        "--output-dir",
        default="outputs/remediation_eval",
        help="Output directory (default: %(default)s)",
    )
    parser.add_argument(
        "--sample-size",
        type=int,
        default=10,
        help="Number of violations to attempt (default: %(default)s)",
    )
    parser.add_argument(
        "--build-command",
        default=None,
        help="Legacy option kept for compatibility (compile behavior comes from apply flow).",
    )
    parser.add_argument(
        "--table-format",
        choices=["md", "tex"],
        default="md",
        help="Table output format (default: %(default)s)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=11,
        help="Random seed for sampling (default: %(default)s)",
    )
    parser.add_argument(
        "--workdir",
        default=None,
        help="Optional working directory to stage benchmark subset",
    )
    parser.add_argument(
        "--max-attempts",
        type=int,
        default=2,
        help="Maximum remediation attempts per violation (default: %(default)s)",
    )
    parser.add_argument(
        "--mode",
        choices=["dry_run", "apply"],
        default="dry_run",
        help="Remediation execution mode (default: %(default)s)",
    )
    parser.add_argument(
        "--reset-neo4j",
        action="store_true",
        help="Clear Neo4j before ingesting benchmark subset",
    )
    return parser.parse_args()


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    args = parse_args()

    context = load_benchmark_evaluation_context(Path(args.config), Path(args.mapping))
    selected_ids = context.selection.selected_testcase_ids

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    with staged_benchmark_workspace(
        benchmark_root=context.benchmark_root,
        java_relative_root=context.selection_cfg["java_relative_root"],
        testcase_ids=selected_ids,
        workdir=args.workdir,
    ) as workspace:
        eval_result = ingest_and_evaluate_subset(
            java_root=workspace.java_root,
            reset_neo4j=args.reset_neo4j,
            logger=LOGGER,
        )
        if eval_result.get("error"):
            LOGGER.error("Policy evaluation failed: %s", eval_result["error"])
            return 1
        violations = eval_result.get("violations") or []

        violations_by_testcase = group_violations_by_testcase(violations)
        category_violations_by_id = collect_category_violations(
            selected_category_ids=context.selected_category_ids,
            categories_by_id=context.categories_by_id,
            selection=context.selection,
            violations_by_testcase=violations_by_testcase,
        )
        candidates: List[Dict[str, Any]] = []
        for category_id in context.selected_category_ids:
            spec = context.categories_by_id.get(category_id)
            if not spec:
                continue
            for violation in category_violations_by_id.get(category_id, []):
                candidate = dict(violation)
                candidate["category"] = spec.label
                candidates.append(candidate)
        if not candidates:
            LOGGER.warning("No candidate violations found for remediation evaluation.")
            return 1

        rng = random.Random(args.seed)
        if len(candidates) > args.sample_size:
            candidates = rng.sample(candidates, k=args.sample_size)

        results: List[Dict[str, Any]] = []
        for violation in candidates:
            violation_id = violation.get("violation_id")
            target_method = violation.get("target_method")
            evidence = violation.get("evidence") or {}
            file_path = evidence.get("file_path") or violation.get("file_path")

            if not violation_id or not target_method or not file_path:
                results.append(
                    {
                        "violation_id": violation_id,
                        "target_method": target_method,
                        "file_path": file_path,
                        "status": "SKIPPED",
                        "error": "missing_violation_fields",
                        "category": violation.get("category"),
                    }
                )
                continue

            apply_result = apply_remediation(
                str(violation_id),
                target_method=str(target_method),
                file_path=str(file_path),
                mode=args.mode,
                max_attempts=args.max_attempts,
                raw_capture_dir=output_dir.as_posix(),
            )
            verification = apply_result.get("verification") or {}
            compilation = apply_result.get("compilation") or {}
            target_rule_status = verification.get("target_rule_status")
            policy_pass = apply_result.get("status") == "OK" and target_rule_status == "PASS"
            build_pass = compilation.get("success") if compilation.get("attempted") else None
            results.append(
                {
                    "violation_id": violation_id,
                    "target_method": target_method,
                    "file_path": file_path,
                    "status": apply_result.get("status"),
                    "error": apply_result.get("error"),
                    "patch_applied": bool(apply_result.get("updated_source_code")),
                    "policy_pass": policy_pass,
                    "build_pass": build_pass,
                    "category": violation.get("category"),
                    "verification": verification,
                    "compilation": compilation,
                    "diff": apply_result.get("diff"),
                    "generation": apply_result.get("generation"),
                    "errors": apply_result.get("errors"),
                    "attempt_count": apply_result.get("attempt_count"),
                    "raw_capture_files": apply_result.get("raw_capture_files"),
                }
            )

    attempted = len(results)
    fix_success = sum(1 for item in results if item.get("policy_pass") is True)
    build_attempted = sum(
        1
        for item in results
        if isinstance(item.get("compilation"), dict) and item["compilation"].get("attempted") is True
    )
    build_success = sum(1 for item in results if item.get("build_pass") is True)
    fix_rate = fix_success / attempted if attempted else 0.0
    build_rate = build_success / build_attempted if build_attempted else 0.0

    metrics = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "benchmark_root": context.benchmark_root.as_posix(),
        "ground_truth_file": context.truth_path.as_posix(),
        "ground_truth_schema": context.truth_schema,
        "selection": context.selection_cfg,
        "coverage_by_category": context.coverage_by_category,
        "mode": args.mode,
        "max_attempts": args.max_attempts,
        "attempted": attempted,
        "fix_success": fix_success,
        "build_attempted": build_attempted,
        "build_success": build_success,
        "fix_success_rate": round(fix_rate, 4),
        "build_success_rate": round(build_rate, 4),
        "legacy_build_command_arg": args.build_command,
        "results": results,
    }

    write_json(output_dir / "remediation_metrics.json", metrics)
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
            "category",
            "error",
        ],
    )

    headers = ["Metric", "Value"]
    table_rows = [
        ["Fix Success Rate", round(fix_rate, 4)],
        ["Build Success Rate", round(build_rate, 4)],
        ["Build Attempts", build_attempted],
        ["Attempted", attempted],
    ]
    if args.table_format == "tex":
        table = render_latex_table(headers, table_rows, caption="Remediation Success Metrics")
        (output_dir / "table.tex").write_text(table, encoding="utf-8")
    else:
        table = render_markdown_table(headers, table_rows)
        (output_dir / "table.md").write_text(table, encoding="utf-8")

    LOGGER.info("Remediation evaluation complete. Outputs written to %s", output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
