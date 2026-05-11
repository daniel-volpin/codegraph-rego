"""
Run OWASP Benchmark evaluation and emit Precision/Recall/F1 metrics.
"""

from __future__ import annotations

import argparse
import json
import logging

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from codegraph.telemetry import install_log_correlation
from codegraph.db import get_neo4j_driver
from codegraph.evaluation.benchmark import (
    CategorySpec,
)
from codegraph.evaluation.io import render_latex_table, render_markdown_table, write_csv, write_json
from codegraph.evaluation.pipeline import (
    ingest_and_evaluate_subset,
    group_violations_by_testcase,
    load_benchmark_evaluation_context,
    staged_benchmark_workspace,
)
from codegraph.evaluation.provenance import collect_provenance, write_provenance
from codegraph.evaluation.uncertainty import bootstrap_prf_ci, wilson_score_ci

LOGGER = logging.getLogger("codegraph.eval.benchmark")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run OWASP Benchmark evaluation.")
    parser.add_argument(
        "--config",
        default="configs/benchmark/baseline.json",
        help="Benchmark selection config JSON (default: %(default)s)",
    )
    parser.add_argument(
        "--mapping",
        default="configs/benchmark/policy_registry.json",
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
    *,
    ci_seed: int | None = 7,
    ci_resamples: int = 2000,
    ci_confidence: float = 0.95,
) -> Dict[str, Any]:
    tp = fp = tn = fn = 0
    outcomes: List[tuple[bool, bool]] = []
    for testcase_id in testcases:
        label = ground_truth.get(testcase_id)
        if label is None:
            continue
        violations = violations_by_testcase.get(testcase_id, [])
        predicted = any(v.get("violation_id") in category.rego_rules for v in violations)
        outcomes.append((bool(predicted), bool(label)))
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

    # Shared resamples keep the P/R/F1 intervals jointly comparable.
    prf_cis = bootstrap_prf_ci(
        outcomes,
        n_resamples=ci_resamples,
        confidence=ci_confidence,
        seed=ci_seed,
    )
    precision_wilson = wilson_score_ci(tp, tp + fp, confidence=ci_confidence)
    recall_wilson = wilson_score_ci(tp, tp + fn, confidence=ci_confidence)

    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "support": len(testcases),
        "precision_ci": prf_cis["precision"],
        "recall_ci": prf_cis["recall"],
        "f1_ci": prf_cis["f1"],
        "precision_ci_wilson": precision_wilson,
        "recall_ci_wilson": recall_wilson,
    }


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s [%(otel_trace_id)s/%(otel_span_id)s] %(message)s",
    )
    install_log_correlation()
    args = parse_args()

    context = load_benchmark_evaluation_context(Path(args.config), Path(args.mapping))
    sampled_by_category = {
        category_id: [rec.testcase_id for rec in records]
        for category_id, records in context.selection.selected_by_category.items()
    }
    sampled_union = sorted({tc for tcs in sampled_by_category.values() for tc in tcs})

    ground_truth_lookup = {rec.testcase_id: rec.label for rec in context.truth_records}
    categories_by_id = context.categories_by_id

    # Bind the CI seed to the selection seed so re-runs of the same
    # config yield byte-identical intervals.
    ci_seed = int(context.selection_cfg.get("seed") or 7)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Write provenance before any work begins so a crash still leaves
    # a manifest on disk.
    provenance = collect_provenance(
        eval_kind="detection",
        config_path=args.config,
        output_dir=output_dir,
        seed=ci_seed,
        llm=None,  # detection eval does not call the LLM.
        extra={
            "mapping_path": str(args.mapping),
            "table_format": args.table_format,
            "reset_neo4j": bool(args.reset_neo4j),
        },
    )
    write_provenance(provenance, output_dir)

    with staged_benchmark_workspace(
        benchmark_root=context.benchmark_root,
        java_relative_root=context.selection_cfg["java_relative_root"],
        testcase_ids=sampled_union,
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

        metrics: Dict[str, Any] = {}
        rows: List[List[Any]] = []
        fn_records: List[Dict[str, Any]] = []
        for category_id in context.selected_category_ids:
            spec = categories_by_id.get(category_id)
            if not spec:
                continue
            testcase_ids = sampled_by_category.get(category_id, [])
            stats = score_category(
                spec,
                ground_truth_lookup,
                testcase_ids,
                violations_by_testcase,
                ci_seed=ci_seed,
            )
            if category_id in context.coverage_by_category and isinstance(stats, dict):
                stats.update(context.coverage_by_category[category_id])
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
            if context.selection_cfg.get("debug_fn_analysis"):
                for testcase_id in testcase_ids:
                    label = ground_truth_lookup.get(testcase_id)
                    if label is not True:
                        continue
                    predicted = any(
                        v.get("violation_id") in spec.rego_rules for v in violations_by_testcase.get(testcase_id, [])
                    )
                    if predicted:
                        continue
                    file_path = workspace.staged_files.get(testcase_id)
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

        all_rules = {rule for spec in context.categories for rule in spec.rego_rules}

    overall = score_category(
        CategorySpec(id="overall", label="Overall", cwes=[], rego_rules=list(all_rules)),
        ground_truth_lookup,
        sampled_union,
        violations_by_testcase,
        ci_seed=ci_seed,
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
        "benchmark_root": context.benchmark_root.as_posix(),
        "ground_truth_file": context.truth_path.as_posix(),
        "ground_truth_schema": context.truth_schema,
        "categories": [spec.__dict__ for spec in context.categories if spec.id in context.selected_category_ids],
        "selection": context.selection_cfg,
        "coverage_by_category": context.coverage_by_category,
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

    if context.selection_cfg.get("debug_fn_analysis") and fn_records:
        fn_path = output_dir / "fn_analysis.jsonl"
        with fn_path.open("w", encoding="utf-8") as handle:
            for record in fn_records:
                handle.write(json.dumps(record) + "\n")

    LOGGER.info("Benchmark evaluation complete. Outputs written to %s", output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
