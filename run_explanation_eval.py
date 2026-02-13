"""
Run citation success evaluation with/without graph context.
"""

from __future__ import annotations

import argparse
import json
import logging
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

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
from codegraph.llm.integration import generate_policy_explanation
from codegraph.policy.integration import evaluate_policies

LOGGER = logging.getLogger("codegraph.eval.explanation")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run citation success evaluation.")
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
        default="outputs/explanation_eval",
        help="Output directory (default: %(default)s)",
    )
    parser.add_argument(
        "--table-format",
        choices=["md", "tex"],
        default="md",
        help="Table output format (default: %(default)s)",
    )
    parser.add_argument(
        "--sample-per-category",
        type=int,
        default=3,
        help="Number of explanation samples to store per category (default: %(default)s)",
    )
    parser.add_argument(
        "--workdir",
        default=None,
        help="Optional working directory to stage benchmark subset",
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


def build_citation_tokens(violation: Dict[str, Any]) -> List[str]:
    evidence = violation.get("evidence") or {}
    tokens: List[str] = []
    file_path = evidence.get("file_path") or violation.get("file_path")
    target_method = evidence.get("target_method") or violation.get("target_method")
    if isinstance(file_path, str):
        tokens.append(file_path)
    if isinstance(target_method, str):
        tokens.append(target_method)
    start_line = evidence.get("start_line")
    end_line = evidence.get("end_line")
    if isinstance(start_line, int):
        tokens.append(f"line {start_line}")
    if isinstance(start_line, int) and isinstance(end_line, int):
        tokens.append(f"lines {start_line}-{end_line}")
    return [token for token in tokens if token]


def has_citation(text: str, tokens: List[str]) -> bool:
    haystack = text.lower()
    return any(token.lower() in haystack for token in tokens if token)


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

        LOGGER.info("Ingesting OWASP Benchmark subset from %s", java_root)
        ingest(java_root.as_posix())

        LOGGER.info("Evaluating policies via OPA/Rego")
        eval_result = evaluate_policies()
        if eval_result.get("error"):
            LOGGER.error("Policy evaluation failed: %s", eval_result["error"])
            return 1
        violations = eval_result.get("violations") or []
    finally:
        if temp_context is not None:
            temp_context.cleanup()

    violations_by_testcase: Dict[str, List[Dict[str, Any]]] = {}
    for violation in violations:
        testcase_id = extract_testcase_id(
            violation.get("target_method") or violation.get("file_path")
        )
        if not testcase_id:
            continue
        violations_by_testcase.setdefault(testcase_id, []).append(violation)

    metrics: Dict[str, Any] = {}
    rows: List[List[Any]] = []
    samples: List[Dict[str, Any]] = []
    samples_per_category: Dict[str, int] = {}
    categories_by_id = {spec.id: spec for spec in categories}
    selected_category_ids = selection_cfg.get("categories") or [spec.id for spec in categories]

    total_with = total_without = total_count = 0

    for category_id in selected_category_ids:
        spec = categories_by_id.get(category_id)
        if not spec:
            continue
        records = selection.selected_by_category.get(category_id, [])
        positive_testcases = {rec.testcase_id for rec in records if rec.label}
        seen_keys: set[Tuple[str, str, str]] = set()
        category_violations: List[Dict[str, Any]] = []
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
                category_violations.append(violation)

        with_success = 0
        without_success = 0
        for violation in category_violations:
            tokens = build_citation_tokens(violation)
            explanation_with = generate_policy_explanation(violation, include_graph_context=True)
            explanation_without = generate_policy_explanation(violation, include_graph_context=False)
            if tokens and has_citation(explanation_with, tokens):
                with_success += 1
            if tokens and has_citation(explanation_without, tokens):
                without_success += 1
            if args.sample_per_category > 0:
                count = samples_per_category.get(category_id, 0)
                if count < args.sample_per_category:
                    samples.append(
                        {
                            "category": spec.label,
                            "violation_id": violation.get("violation_id"),
                            "target_method": violation.get("target_method"),
                            "file_path": violation.get("file_path"),
                            "evidence_tokens": tokens,
                            "explanation_with_context": explanation_with,
                            "explanation_without_context": explanation_without,
                        }
                    )
                    samples_per_category[category_id] = count + 1

        count = len(category_violations)
        rate_with = with_success / count if count else 0.0
        rate_without = without_success / count if count else 0.0
        metrics[category_id] = {
            "count": count,
            "with_context": with_success,
            "without_context": without_success,
            "rate_with_context": round(rate_with, 4),
            "rate_without_context": round(rate_without, 4),
        }
        rows.append(
            [
                spec.label,
                count,
                round(rate_with, 4),
                round(rate_without, 4),
            ]
        )
        total_with += with_success
        total_without += without_success
        total_count += count

    overall_rate_with = total_with / total_count if total_count else 0.0
    overall_rate_without = total_without / total_count if total_count else 0.0
    metrics["overall"] = {
        "count": total_count,
        "with_context": total_with,
        "without_context": total_without,
        "rate_with_context": round(overall_rate_with, 4),
        "rate_without_context": round(overall_rate_without, 4),
    }
    rows.append(["Overall", total_count, round(overall_rate_with, 4), round(overall_rate_without, 4)])

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "benchmark_root": benchmark_root.as_posix(),
        "ground_truth_file": truth_path.as_posix(),
        "ground_truth_schema": truth_schema,
        "selection": selection_cfg,
        "metrics": metrics,
        "sample_count": len(samples),
    }

    write_json(output_dir / "citation_metrics.json", payload)
    write_csv(
        output_dir / "citation_metrics.csv",
        [
            {
                "category": row[0],
                "count": row[1],
                "citation_rate_with_context": row[2],
                "citation_rate_without_context": row[3],
            }
            for row in rows
        ],
        fieldnames=["category", "count", "citation_rate_with_context", "citation_rate_without_context"],
    )

    if samples:
        with (output_dir / "explanation_samples.jsonl").open("w", encoding="utf-8") as handle:
            for sample in samples:
                handle.write(json.dumps(sample) + "\n")

    headers = ["Category", "TP Count", "Citation@Context", "Citation@NoContext"]
    if args.table_format == "tex":
        table = render_latex_table(headers, rows, caption="Citation Success Rates")
        (output_dir / "table.tex").write_text(table, encoding="utf-8")
    else:
        table = render_markdown_table(headers, rows)
        (output_dir / "table.md").write_text(table, encoding="utf-8")

    LOGGER.info("Explanation evaluation complete. Outputs written to %s", output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
