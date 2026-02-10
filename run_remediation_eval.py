"""
Run remediation success evaluation on a small subset of violations.
"""

from __future__ import annotations

import argparse
import json
import logging
import random
import shutil
import subprocess
import tempfile
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

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
from codegraph.ingestion.service import ingest, process_single_file
from codegraph.policy.integration import PolicyEvaluator, evaluate_policies
from codegraph.remediation.service import RemediationService

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
        help="Build/compile command to run in each case directory",
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
        "--reset-neo4j",
        action="store_true",
        help="Clear Neo4j before each ingestion (recommended for deterministic results)",
    )
    return parser.parse_args()


def clear_graph() -> None:
    driver = get_neo4j_driver()
    try:
        with driver.session() as session:
            session.run("MATCH (n) DETACH DELETE n").consume()
    finally:
        driver.close()


def apply_method_replacement(
    file_path: Path,
    updated_source: str,
    start_line: Optional[int],
    end_line: Optional[int],
    fallback_snippet: str,
) -> bool:
    if not file_path.is_file():
        return False
    lines = file_path.read_text(encoding="utf-8").splitlines()
    dedented = textwrap.dedent(updated_source).strip("\n")
    replacement_lines = dedented.splitlines()
    if start_line and end_line and 1 <= start_line <= end_line <= len(lines):
        lines[start_line - 1 : end_line] = replacement_lines
        file_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return True
    if fallback_snippet and fallback_snippet in "\n".join(lines):
        updated = "\n".join(lines).replace(fallback_snippet, dedented, 1)
        file_path.write_text(updated, encoding="utf-8")
        return True
    return False


def evaluate_fix(policy_evaluator: PolicyEvaluator, target_method: str, violation_id: str) -> bool:
    result = policy_evaluator.evaluate(target_method)
    violations = result.get("violations") or []
    return not any(v.get("violation_id") == violation_id for v in violations)


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

    base_subset_root = work_root / "base_subset"
    base_subset_root.mkdir(parents=True, exist_ok=True)

    try:
        stage_benchmark_subset(
            benchmark_root,
            selection_cfg["java_relative_root"],
            selected_ids,
            base_subset_root,
        )
        base_java_root = base_subset_root / selection_cfg["java_relative_root"]

        if args.reset_neo4j:
            clear_graph()

        LOGGER.info("Ingesting base subset from %s", base_java_root)
        ingest(base_java_root.as_posix())

        eval_result = evaluate_policies()
        if eval_result.get("error"):
            LOGGER.error("Policy evaluation failed: %s", eval_result["error"])
            return 1
        violations = eval_result.get("violations") or []

        violations_by_testcase: Dict[str, List[Dict[str, Any]]] = {}
        for violation in violations:
            testcase_id = extract_testcase_id(
                violation.get("target_method") or violation.get("file_path")
            )
            if not testcase_id:
                continue
            violations_by_testcase.setdefault(testcase_id, []).append(violation)

        categories_by_id = {spec.id: spec for spec in categories}
        selected_category_ids = selection_cfg.get("categories") or [spec.id for spec in categories]

        candidate_violations: List[Dict[str, Any]] = []
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
                    candidate = dict(violation)
                    candidate["category"] = spec.label
                    candidate_violations.append(candidate)

        if not candidate_violations:
            LOGGER.warning("No candidate violations found for remediation evaluation.")
            return 1

        rng = random.Random(args.seed)
        if len(candidate_violations) > args.sample_size:
            candidate_violations = rng.sample(candidate_violations, k=args.sample_size)

        results: List[Dict[str, Any]] = []
        policy_evaluator = PolicyEvaluator()
        remediation_service = RemediationService()
        build_command = args.build_command or selection_cfg.get("build_command")

        for idx, violation in enumerate(candidate_violations, start=1):
            case_dir = output_dir / f"case_{idx:03d}"
            if case_dir.exists():
                shutil.rmtree(case_dir)
            shutil.copytree(base_subset_root, case_dir)
            case_java_root = case_dir / selection_cfg["java_relative_root"]

            if args.reset_neo4j:
                clear_graph()

            LOGGER.info("Ingesting case %d from %s", idx, case_java_root)
            ingest(case_java_root.as_posix())

            target_method = violation.get("target_method")
            violation_id = violation.get("violation_id")
            evidence = violation.get("evidence") or {}
            file_path = evidence.get("file_path") or violation.get("file_path")
            start_line = evidence.get("start_line")
            end_line = evidence.get("end_line")
            source_code = evidence.get("source_code") or ""

            if not target_method or not file_path or not violation_id:
                results.append(
                    {
                        "violation_id": violation_id,
                        "target_method": target_method,
                        "file_path": file_path,
                        "status": "skipped",
                        "error": "missing_target_method_or_file_path",
                    }
                )
                continue

            try:
                rel_path = Path(file_path).relative_to(base_java_root)
            except ValueError:
                rel_path = Path(file_path).name
            case_file_path = case_java_root / rel_path

            preview = remediation_service.preview_virtual_fix(
                violation_id,
                target_method=target_method,
                file_path=case_file_path.as_posix(),
            )
            if preview.get("status") != "OK":
                results.append(
                    {
                        "violation_id": violation_id,
                        "target_method": target_method,
                        "file_path": case_file_path.as_posix(),
                        "status": "preview_failed",
                        "error": preview.get("error"),
                    }
                )
                continue

            updated_source = preview.get("updated_source_code") or ""
            patch_applied = apply_method_replacement(
                case_file_path, updated_source, start_line, end_line, source_code
            )

            policy_pass = False
            if patch_applied:
                try:
                    process_single_file(case_file_path.as_posix())
                    policy_pass = evaluate_fix(policy_evaluator, target_method, violation_id)
                except Exception as exc:
                    LOGGER.error("Policy evaluation failed after patch: %s", exc)

            build_pass = None
            build_output = None
            if build_command:
                proc = subprocess.run(
                    build_command,
                    shell=True,
                    cwd=case_dir.as_posix(),
                    capture_output=True,
                    text=True,
                )
                build_pass = proc.returncode == 0
                build_output = (proc.stdout or "") + (proc.stderr or "")

            results.append(
                {
                    "violation_id": violation_id,
                    "target_method": target_method,
                    "file_path": case_file_path.as_posix(),
                    "patch_applied": patch_applied,
                    "policy_pass": policy_pass,
                    "build_pass": build_pass,
                    "build_output": build_output,
                    "category": violation.get("category"),
                }
            )
    finally:
        if temp_context is not None:
            temp_context.cleanup()

    attempted = len(results)
    fix_success = sum(1 for item in results if item.get("policy_pass"))
    build_success = sum(1 for item in results if item.get("build_pass") is True)
    fix_rate = fix_success / attempted if attempted else 0.0
    build_rate = build_success / attempted if attempted else 0.0

    metrics = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "benchmark_root": benchmark_root.as_posix(),
        "ground_truth_file": truth_path.as_posix(),
        "ground_truth_schema": truth_schema,
        "selection": selection_cfg,
        "attempted": attempted,
        "fix_success": fix_success,
        "build_success": build_success,
        "fix_success_rate": round(fix_rate, 4),
        "build_success_rate": round(build_rate, 4),
        "build_command": build_command,
        "results": results,
    }

    write_json(output_dir / "remediation_metrics.json", metrics)
    write_csv(
        output_dir / "remediation_metrics.csv",
        [
            {
                "violation_id": item.get("violation_id"),
                "target_method": item.get("target_method"),
                "patch_applied": item.get("patch_applied"),
                "policy_pass": item.get("policy_pass"),
                "build_pass": item.get("build_pass"),
                "category": item.get("category"),
            }
            for item in results
        ],
        fieldnames=[
            "violation_id",
            "target_method",
            "patch_applied",
            "policy_pass",
            "build_pass",
            "category",
        ],
    )

    headers = ["Metric", "Value"]
    table_rows = [
        ["Fix Success Rate", round(fix_rate, 4)],
        ["Build Success Rate", round(build_rate, 4)],
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
