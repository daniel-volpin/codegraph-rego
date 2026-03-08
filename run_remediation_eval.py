"""
Run remediation success evaluation using the same apply/verify flow as the API.
"""

from __future__ import annotations

import argparse
import logging
import random
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
from codegraph.evaluation.remediation_runtime import (
    RemediationRuntime,
    build_metrics_payload,
    build_remediation_result,
    build_skipped_result,
    write_final_artifacts,
)

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
    runtime = RemediationRuntime(
        output_dir=output_dir,
        benchmark_root=context.benchmark_root,
        truth_path=context.truth_path,
        truth_schema=context.truth_schema,
        selection_cfg=context.selection_cfg,
        coverage_by_category=context.coverage_by_category,
        mode=args.mode,
        max_attempts=args.max_attempts,
    )
    runtime.write_stage_progress(
        "selection",
        "Loaded benchmark remediation context",
        selected_testcases=len(selected_ids),
    )
    completed = False
    try:
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
            runtime.begin(total_cases=len(candidates))
            for violation in candidates:
                case_id, case_dir = runtime.prepare_case(violation)
                violation_id = violation.get("violation_id")
                target_method = violation.get("target_method")
                evidence = violation.get("evidence") or {}
                file_path = evidence.get("file_path") or violation.get("file_path")

                if not violation_id or not target_method or not file_path:
                    result = build_skipped_result(
                        violation=violation,
                        case_id=case_id,
                        error="missing_violation_fields",
                    )
                    results.append(result)
                    runtime.record_case(apply_result=result, result=result)
                    continue

                apply_result = apply_remediation(
                    str(violation_id),
                    target_method=str(target_method),
                    file_path=str(file_path),
                    mode=args.mode,
                    max_attempts=args.max_attempts,
                    raw_capture_dir=case_dir.as_posix(),
                    build_command=args.build_command or context.selection_cfg.get("build_command"),
                )
                result = build_remediation_result(
                    violation=violation,
                    apply_result=apply_result,
                    case_id=case_id,
                )
                results.append(result)
                runtime.record_case(apply_result=apply_result, result=result)

        metrics = build_metrics_payload(
            benchmark_root=context.benchmark_root,
            truth_path=context.truth_path,
            truth_schema=context.truth_schema,
            selection_cfg=context.selection_cfg,
            coverage_by_category=context.coverage_by_category,
            mode=args.mode,
            max_attempts=args.max_attempts,
            legacy_build_command_arg=args.build_command,
            results=results,
        )
        write_final_artifacts(output_dir, metrics, table_format=args.table_format)
        runtime.finalize(status="completed")
        completed = True
    finally:
        if not completed:
            runtime.finalize(status="failed")

    LOGGER.info("Remediation evaluation complete. Outputs written to %s", output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
