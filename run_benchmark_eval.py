"""
Run OWASP Benchmark evaluation and emit Precision/Recall/F1 metrics.
"""

from __future__ import annotations

import argparse
import json
import logging
import tempfile

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from codegraph.db import get_neo4j_driver
from codegraph.evaluation.benchmark import (
    CategorySpec,
    coverage_report,
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

LOGGER = logging.getLogger("codegraph.eval.benchmark")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run OWASP Benchmark evaluation.")
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
        default="outputs/benchmark_eval",
        help="Output directory (default: %(default)s)",
    )
    parser.add_argument(
        "--table-format",
        choices=["md", "tex"],
        default="md",
        help="Table output format (default: %(default)s)",
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


def extract_api_occurrences(
    file_path: Path,
    terms: List[str],
    context_lines: int = 3,
) -> List[Dict[str, Any]]:
    if not file_path.is_file():
        return []
    lines = file_path.read_text(encoding="utf-8").splitlines()
    occurrences: List[Dict[str, Any]] = []
    lowered_terms = [term.lower() for term in terms]
    for idx, line in enumerate(lines):
        if any(term in line.lower() for term in lowered_terms):
            start = max(0, idx - context_lines)
            end = min(len(lines), idx + context_lines + 1)
            occurrences.append(
                {
                    "line": idx + 1,
                    "matched_line": line.strip(),
                    "context": "\n".join(lines[start:end]),
                }
            )
    return occurrences


def fetch_graph_debug(file_path: Optional[str]) -> Dict[str, Any]:
    if not file_path:
        return {}
    driver = get_neo4j_driver()
    try:
        with driver.session() as session:
            cypher = (
                "MATCH (m:Method {file_path: $path}) "
                "OPTIONAL MATCH (m)-[:CALLS]->(callee:Method) "
                "RETURN coalesce(m.full_signature, m.signature) AS signature, "
                "       m.annotations AS annotations, "
                "       collect(DISTINCT coalesce(callee.full_signature, callee.signature)) AS calls"
            )
            rows = [record.data() for record in session.run(cypher, path=file_path)]
    finally:
        driver.close()
    return {"file_path": file_path, "methods": rows}


def score_category(
    category: CategorySpec,
    ground_truth: Dict[str, bool],
    testcases: List[str],
    violations_by_testcase: Dict[str, List[Dict[str, Any]]],
) -> Dict[str, Any]:
    tp = fp = tn = fn = 0
    for testcase_id in testcases:
        label = ground_truth.get(testcase_id)
        if label is None:
            continue
        violations = violations_by_testcase.get(testcase_id, [])
        predicted = any(v.get("violation_id") in category.rego_rules for v in violations)
        if label and predicted:
            tp += 1
        elif label and not predicted:
            fn += 1
        elif not label and predicted:
            fp += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "support": len(testcases),
    }


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    args = parse_args()

    selection_cfg = load_selection_config(Path(args.config))
    categories = load_mapping_config(Path(args.mapping))
    benchmark_root = Path(selection_cfg["benchmark_root"])

    truth_path = find_ground_truth_file(benchmark_root, selection_cfg.get("ground_truth_path"))
    truth_schema = inspect_ground_truth_schema(truth_path)
    truth_records = load_ground_truth(benchmark_root, truth_path.as_posix())
    selection = select_testcases(truth_records, categories, selection_cfg)
    sampled_by_category = {
        category_id: [rec.testcase_id for rec in records]
        for category_id, records in selection.selected_by_category.items()
    }
    sampled_union = sorted({tc for tcs in sampled_by_category.values() for tc in tcs})

    ground_truth_lookup = {rec.testcase_id: rec.label for rec in truth_records}
    categories_by_id = {spec.id: spec for spec in categories}
    selected_category_ids = selection_cfg.get("categories") or [spec.id for spec in categories]
    coverage_by_category = coverage_report(selection, selected_category_ids)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.workdir:
        work_root = Path(args.workdir)
        work_root.mkdir(parents=True, exist_ok=True)
        temp_context = None
    else:
        temp_context = tempfile.TemporaryDirectory()
        work_root = Path(temp_context.name)

    staged_files = stage_benchmark_subset(
        benchmark_root,
        selection_cfg["java_relative_root"],
        sampled_union,
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

    violations_by_testcase: Dict[str, List[Dict[str, Any]]] = {}
    for violation in violations:
        testcase_id = extract_testcase_id(violation.get("target_method") or violation.get("file_path"))
        if not testcase_id:
            continue
        violations_by_testcase.setdefault(testcase_id, []).append(violation)

    metrics: Dict[str, Any] = {}
    rows: List[List[Any]] = []
    fn_records: List[Dict[str, Any]] = []
    for category_id in selected_category_ids:
        spec = categories_by_id.get(category_id)
        if not spec:
            continue
        testcase_ids = sampled_by_category.get(category_id, [])
        stats = score_category(spec, ground_truth_lookup, testcase_ids, violations_by_testcase)
        if category_id in coverage_by_category and isinstance(stats, dict):
            stats.update(coverage_by_category[category_id])
        metrics[category_id] = stats
        rows.append(
            [
                spec.label,
                stats["tp"],
                stats["fp"],
                stats["fn"],
                stats["precision"],
                stats["recall"],
                stats["f1"],
            ]
        )
        if selection_cfg.get("debug_fn_analysis"):
            for testcase_id in testcase_ids:
                label = ground_truth_lookup.get(testcase_id)
                if label is not True:
                    continue
                predicted = any(
                    v.get("violation_id") in spec.rego_rules for v in violations_by_testcase.get(testcase_id, [])
                )
                if predicted:
                    continue
                file_path = staged_files.get(testcase_id)
                occurrences = []
                if file_path:
                    occurrences = extract_api_occurrences(
                        file_path,
                        terms=[
                            "MD5",
                            "MessageDigest",
                            "Cipher",
                            "Random",
                            "SecureRandom",
                            "Math.random",
                            "java.sql",
                            "Statement",
                            "PreparedStatement",
                            "executeQuery",
                            "executeUpdate",
                            "prepareStatement",
                        ],
                        context_lines=3,
                    )
                fn_records.append(
                    {
                        "testcase_id": testcase_id,
                        "category_id": category_id,
                        "file_path": file_path.as_posix() if file_path else None,
                        "matched_api_occurrences": occurrences,
                        "graph_query_debug": fetch_graph_debug(file_path.as_posix() if file_path else None),
                    }
                )

    all_rules = {rule for spec in categories for rule in spec.rego_rules}
    overall = score_category(
        CategorySpec(id="overall", label="Overall", cwes=[], rego_rules=list(all_rules)),
        ground_truth_lookup,
        sampled_union,
        violations_by_testcase,
    )
    metrics["overall"] = overall
    rows.append(
        [
            "Overall",
            overall["tp"],
            overall["fp"],
            overall["fn"],
            overall["precision"],
            overall["recall"],
            overall["f1"],
        ]
    )

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "benchmark_root": benchmark_root.as_posix(),
        "ground_truth_file": truth_path.as_posix(),
        "ground_truth_schema": truth_schema,
        "categories": [spec.__dict__ for spec in categories if spec.id in selected_category_ids],
        "selection": selection_cfg,
        "coverage_by_category": coverage_by_category,
        "metrics": metrics,
        "violation_count": len(violations),
        "sampled_testcases_by_category": sampled_by_category,
        "selected_testcases": sampled_union,
    }

    write_json(output_dir / "metrics.json", payload)
    write_csv(
        output_dir / "metrics.csv",
        [
            {
                "category": row[0],
                "tp": row[1],
                "fp": row[2],
                "fn": row[3],
                "precision": row[4],
                "recall": row[5],
                "f1": row[6],
            }
            for row in rows
        ],
        fieldnames=["category", "tp", "fp", "fn", "precision", "recall", "f1"],
    )

    headers = ["Category", "TP", "FP", "FN", "Precision", "Recall", "F1"]
    if args.table_format == "tex":
        table = render_latex_table(headers, rows, caption="Benchmark Evaluation Metrics")
        (output_dir / "table.tex").write_text(table, encoding="utf-8")
    else:
        table = render_markdown_table(headers, rows)
        (output_dir / "table.md").write_text(table, encoding="utf-8")

    if selection_cfg.get("debug_fn_analysis") and fn_records:
        fn_path = output_dir / "fn_analysis.jsonl"
        with fn_path.open("w", encoding="utf-8") as handle:
            for record in fn_records:
                handle.write(json.dumps(record) + "\n")

    if temp_context is not None:
        temp_context.cleanup()

    LOGGER.info("Benchmark evaluation complete. Outputs written to %s", output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
