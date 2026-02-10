"""
Run remediation success evaluation using the same apply/verify flow as the API.
"""

from __future__ import annotations

import argparse
import logging
import random
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from codegraph.api.services.remediation_service import apply_remediation
from codegraph.db import get_neo4j_driver
from codegraph.evaluation.benchmark import (
    extract_testcase_id,
    find_ground_truth_file,
    inspect_ground_truth_schema,
    load_ground_truth,
    load_mapping_config,
    load_selection_config,
    select_testcases,
    stage_benchmark_subset,
)
from codegraph.evaluation.io import render_latex_table, render_markdown_table, write_csv, write_json
from codegraph.ingestion.service import ingest
from codegraph.policy.integration import evaluate_policies

LOGGER = logging.getLogger("codegraph.eval.remediation")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run remediation success evaluation.")
    parser.add_argument(
        "--config",
        default="configs/benchmark_selection.json",
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


def clear_graph() -> None:
    driver = get_neo4j_driver()
    try:
        with driver.session() as session:
            session.run("MATCH (n) DETACH DELETE n").consume()
    finally:
        driver.close()


def _build_candidate_violations(
    violations: List[Dict[str, Any]],
    selection_cfg: Dict[str, Any],
    categories: List[Any],
    selection: Any,
) -> List[Dict[str, Any]]:
    categories_by_id = {spec.id: spec for spec in categories}
    selected_category_ids = selection_cfg.get("categories") or [spec.id for spec in categories]

    violations_by_testcase: Dict[str, List[Dict[str, Any]]] = {}
    for violation in violations:
        testcase_id = extract_testcase_id(
            violation.get("target_method") or violation.get("file_path")
        )
        if not testcase_id:
            continue
        violations_by_testcase.setdefault(testcase_id, []).append(violation)

    candidates: List[Dict[str, Any]] = []
    seen_keys: set[tuple[str, str, str]] = set()
    for category_id in selected_category_ids:
        spec = categories_by_id.get(category_id)
        if not spec:
            continue
        records = selection.selected_by_category.get(category_id, [])
        positive_testcases = {rec.testcase_id for rec in records if rec.label}
        for testcase_id in positive_testcases:
            for violation in violations_by_testcase.get(testcase_id, []):
                if violation.get("violation_id") not in spec.rego_rules:
                    continue
                key = (
                    str(violation.get("violation_id")),
                    str(violation.get("target_method")),
                    str(violation.get("file_path")),
                )
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                candidate = dict(violation)
                candidate["category"] = spec.label
                candidates.append(candidate)
    return candidates


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    args = parse_args()

    selection_cfg = load_selection_config(Path(args.config))
    categories = load_mapping_config(Path(args.mapping))
    benchmark_root = Path(selection_cfg["benchmark_root"])
    truth_path = find_ground_truth_file(
        benchmark_root, selection_cfg.get("ground_truth_path")
    )
    truth_schema = inspect_ground_truth_schema(truth_path)
    truth_records = load_ground_truth(benchmark_root, truth_path.as_posix())
    selection = select_testcases(truth_records, categories, selection_cfg)
    selected_ids = selection.selected_testcase_ids

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.workdir:
        work_root = Path(args.workdir)
        work_root.mkdir(parents=True, exist_ok=True)
        temp_context = None
    else:
        temp_context = tempfile.TemporaryDirectory()
        work_root = Path(temp_context.name)

    try:
        stage_benchmark_subset(
            benchmark_root,
            selection_cfg["java_relative_root"],
            selected_ids,
            work_root,
        )
        java_root = work_root / selection_cfg["java_relative_root"]

        if args.reset_neo4j:
            clear_graph()

        LOGGER.info("Ingesting benchmark subset from %s", java_root)
        ingest(java_root.as_posix())

        eval_result = evaluate_policies()
        if eval_result.get("error"):
            LOGGER.error("Policy evaluation failed: %s", eval_result["error"])
            return 1
        violations = eval_result.get("violations") or []

        candidates = _build_candidate_violations(violations, selection_cfg, categories, selection)
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
            )
            verification = apply_result.get("verification") or {}
            compilation = apply_result.get("compilation") or {}
            target_rule_status = verification.get("target_rule_status")
            policy_pass = (
                apply_result.get("status") == "OK"
                and target_rule_status == "PASS"
            )
            build_pass = (
                compilation.get("success")
                if compilation.get("attempted")
                else None
            )
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
                }
            )
    finally:
        if temp_context is not None:
            temp_context.cleanup()

    attempted = len(results)
    fix_success = sum(1 for item in results if item.get("policy_pass") is True)
    build_attempted = sum(
        1
        for item in results
        if isinstance(item.get("compilation"), dict)
        and item["compilation"].get("attempted") is True
    )
    build_success = sum(1 for item in results if item.get("build_pass") is True)
    fix_rate = fix_success / attempted if attempted else 0.0
    build_rate = build_success / build_attempted if build_attempted else 0.0

    metrics = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "benchmark_root": benchmark_root.as_posix(),
        "ground_truth_file": truth_path.as_posix(),
        "ground_truth_schema": truth_schema,
        "selection": selection_cfg,
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
