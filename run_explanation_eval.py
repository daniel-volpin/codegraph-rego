"""
Run citation success evaluation with/without graph context.
"""

from __future__ import annotations

import argparse
import logging
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from time import perf_counter
from typing import Any, Dict, List, Optional

from codegraph.config import settings
from codegraph.evaluation.explanation_runtime import ExplanationRuntime, utc_now_iso
from codegraph.evaluation.io import render_latex_table, render_markdown_table, write_csv, write_json
from codegraph.evaluation.pipeline import (
    collect_category_violations,
    group_violations_by_testcase as index_violations_by_testcase,
    ingest_and_evaluate_subset,
    load_benchmark_evaluation_context,
    staged_benchmark_workspace,
)
from codegraph.llm.evidence_cards import format_citation
from codegraph.llm.explanation_prompting import build_explanation_evidence, build_explanation_prompt
from codegraph.llm.integration import (
    generate_policy_explanation_structured,
    render_policy_explanation_structured,
)

LOGGER = logging.getLogger("codegraph.eval.explanation")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run citation success evaluation.")
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
    parser.add_argument(
        "--evidence-mode",
        choices=["full", "lean"],
        default="lean",
        help="Explanation evidence mode (default: %(default)s)",
    )
    parser.add_argument(
        "--llm-max-tokens-eval",
        type=int,
        default=192,
        help="Maximum tokens for explanation-eval LLM calls (default: %(default)s)",
    )
    return parser.parse_args()


def build_expected_citation(
    violation: Dict[str, Any],
    *,
    include_graph_context: bool,
    evidence_mode: str,
) -> Optional[str]:
    payload = build_explanation_evidence(
        violation,
        include_graph_context=include_graph_context,
        evidence_mode=evidence_mode,
    )
    evidence_cards = payload.get("evidence_cards") or []
    if evidence_cards:
        citation = evidence_cards[0].get("citation")
        if isinstance(citation, str) and citation.strip() and citation != "No file citation available":
            return citation.strip()

    citation = format_citation(
        payload.get("file_path"),
        payload.get("start_line"),
        payload.get("end_line"),
    )
    if citation == "No file citation available":
        return None
    return citation


def has_exact_citation(explanation_payload: Dict[str, Any] | None, expected_citation: str | None) -> bool:
    if not expected_citation or not isinstance(explanation_payload, dict):
        return False
    actual_citation = explanation_payload.get("citation")
    if not isinstance(actual_citation, str):
        return False
    return actual_citation.strip() == expected_citation

def _measure_prompt_chars(messages: List[Dict[str, str]]) -> int:
    return sum(len(message.get("content", "")) for message in messages)


def _run_explanation_request(
    *,
    violation: Dict[str, Any],
    include_graph_context: bool,
    evidence_mode: str,
    max_tokens: int,
) -> Dict[str, Any]:
    messages = build_explanation_prompt(
        violation,
        include_graph_context=include_graph_context,
        evidence_mode=evidence_mode,
    )
    prompt_chars = _measure_prompt_chars(messages)
    started = perf_counter()
    error = None
    structured_explanation: Dict[str, Any] | None = None
    try:
        structured_explanation = generate_policy_explanation_structured(
            violation,
            include_graph_context=include_graph_context,
            evidence_mode=evidence_mode,
            max_tokens=max_tokens,
        )
        explanation = render_policy_explanation_structured(structured_explanation)
    except Exception as exc:  # pragma: no cover - defensive runtime guard
        explanation = f"[LLM unavailable: unexpected error: {exc}]"
        error = str(exc)
    latency_ms = round((perf_counter() - started) * 1000, 2)
    return {
        "explanation": explanation,
        "structured_explanation": structured_explanation,
        "prompt_chars": prompt_chars,
        "response_chars": len(explanation),
        "latency_ms": latency_ms,
        "error": error,
    }


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    args = parse_args()

    context = load_benchmark_evaluation_context(Path(args.config), Path(args.mapping))
    selected_ids = context.selection.selected_testcase_ids

    output_dir = Path(args.output_dir)
    runtime = ExplanationRuntime(
        output_dir=output_dir,
        benchmark_root=context.benchmark_root,
        truth_path=context.truth_path,
        truth_schema=context.truth_schema,
        selection_cfg=context.selection_cfg,
        coverage_by_category=context.coverage_by_category,
        sample_per_category=args.sample_per_category,
        evidence_mode=args.evidence_mode,
        llm_max_tokens_eval=args.llm_max_tokens_eval,
    )
    runtime.write_stage_progress("initialization", "Loading configs and benchmark ground truth")
    runtime.write_stage_progress(
        "selection",
        "Benchmark subset selected",
        selected_testcases=len(selected_ids),
        selected_categories=context.selected_category_ids,
    )

    with staged_benchmark_workspace(
        benchmark_root=context.benchmark_root,
        java_relative_root=context.selection_cfg["java_relative_root"],
        testcase_ids=selected_ids,
        workdir=args.workdir,
    ) as workspace:
        runtime.write_stage_progress(
            "ingestion",
            "Ingesting selected benchmark subset into Neo4j",
            selected_testcases=len(selected_ids),
            java_root=workspace.java_root.as_posix(),
        )
        runtime.write_stage_progress("policy_evaluation", "Evaluating policies via OPA/Rego")
        eval_result = ingest_and_evaluate_subset(
            java_root=workspace.java_root,
            reset_neo4j=args.reset_neo4j,
            logger=LOGGER,
        )
        if eval_result.get("error"):
            LOGGER.error("Policy evaluation failed: %s", eval_result["error"])
            runtime.write_stage_progress("policy_evaluation", "Policy evaluation failed", error=eval_result["error"])
            runtime.finalize(status="failed", metrics={})
            return 1
        violations = eval_result.get("violations") or []

    violations_by_testcase = index_violations_by_testcase(violations)

    metrics: Dict[str, Any] = {}
    samples_per_category: Dict[str, int] = {}
    categories_by_id = context.categories_by_id
    runtime.write_stage_progress(
        "violation_indexing",
        "Grouping policy violations by category",
        detected_violations=len(violations),
    )

    category_violations_by_id = collect_category_violations(
        selected_category_ids=context.selected_category_ids,
        categories_by_id=categories_by_id,
        selection=context.selection,
        violations_by_testcase=violations_by_testcase,
    )
    total_target_violations = sum(len(vios) for vios in category_violations_by_id.values())
    runtime.begin_explanations(total_target_violations=total_target_violations, metrics=metrics)
    interrupted = False

    try:
        with ThreadPoolExecutor(max_workers=max(1, settings.llm_concurrency)) as pool:
            for category_id in context.selected_category_ids:
                spec = categories_by_id.get(category_id)
                if not spec:
                    continue
                category_violations = category_violations_by_id.get(category_id, [])
                runtime.start_category(
                    category_id=category_id,
                    category_label=spec.label,
                    category_total=len(category_violations),
                    metrics=metrics,
                )
                with_success = 0
                without_success = 0
                metrics[category_id] = {
                    "count": 0,
                    "with_context": 0,
                    "without_context": 0,
                    "rate_with_context": 0.0,
                    "rate_without_context": 0.0,
                }
                if category_id in context.coverage_by_category:
                    metrics[category_id].update(context.coverage_by_category[category_id])

                for idx, violation in enumerate(category_violations, start=1):
                    with_expected_citation = build_expected_citation(
                        violation,
                        include_graph_context=True,
                        evidence_mode=args.evidence_mode,
                    )
                    without_expected_citation = build_expected_citation(
                        violation,
                        include_graph_context=False,
                        evidence_mode=args.evidence_mode,
                    )
                    fut_with = pool.submit(
                        _run_explanation_request,
                        violation=violation,
                        include_graph_context=True,
                        evidence_mode=args.evidence_mode,
                        max_tokens=args.llm_max_tokens_eval,
                    )
                    fut_without = pool.submit(
                        _run_explanation_request,
                        violation=violation,
                        include_graph_context=False,
                        evidence_mode=args.evidence_mode,
                        max_tokens=args.llm_max_tokens_eval,
                    )
                    with_result = fut_with.result()
                    without_result = fut_without.result()

                    explanation_with = with_result["explanation"]
                    explanation_without = without_result["explanation"]
                    with_hit = has_exact_citation(with_result.get("structured_explanation"), with_expected_citation)
                    without_hit = has_exact_citation(
                        without_result.get("structured_explanation"),
                        without_expected_citation,
                    )
                    if with_hit:
                        with_success += 1
                    if without_hit:
                        without_success += 1

                    base_metric = {
                        "timestamp": utc_now_iso(),
                        "category_id": category_id,
                        "category_label": spec.label,
                        "violation_id": violation.get("violation_id"),
                        "target_method": violation.get("target_method"),
                        "evidence_mode": args.evidence_mode,
                        "max_tokens": args.llm_max_tokens_eval,
                    }
                    runtime.write_request_metric(
                        {
                            **base_metric,
                            "context_mode": "with_context",
                            "prompt_chars": with_result["prompt_chars"],
                            "response_chars": with_result["response_chars"],
                            "latency_ms": with_result["latency_ms"],
                            "citation_hit": with_hit,
                            "error": with_result["error"],
                        }
                    )
                    runtime.write_request_metric(
                        {
                            **base_metric,
                            "context_mode": "without_context",
                            "prompt_chars": without_result["prompt_chars"],
                            "response_chars": without_result["response_chars"],
                            "latency_ms": without_result["latency_ms"],
                            "citation_hit": without_hit,
                            "error": without_result["error"],
                        }
                    )

                    if args.sample_per_category > 0:
                        count = samples_per_category.get(category_id, 0)
                        if count < args.sample_per_category:
                            sample = {
                                "category": spec.label,
                                "violation_id": violation.get("violation_id"),
                                "target_method": violation.get("target_method"),
                                "file_path": violation.get("file_path"),
                                "expected_citation_with_context": with_expected_citation,
                                "expected_citation_without_context": without_expected_citation,
                                "evidence_mode": args.evidence_mode,
                                "explanation_with_context": explanation_with,
                                "explanation_without_context": explanation_without,
                            }
                            runtime.write_sample(sample)
                            samples_per_category[category_id] = count + 1

                    metrics[category_id] = {
                        **metrics[category_id],
                        "count": idx,
                        "with_context": with_success,
                        "without_context": without_success,
                        "rate_with_context": round((with_success / idx) if idx else 0.0, 4),
                        "rate_without_context": round((without_success / idx) if idx else 0.0, 4),
                    }
                    runtime.record_violation_result(
                        with_context_hit=with_hit,
                        without_context_hit=without_hit,
                        metrics=metrics,
                    )
    except KeyboardInterrupt:
        interrupted = True
        LOGGER.warning("Interrupted by user. Writing partial artifacts to %s", output_dir)
        runtime.close()

    rows: List[List[Any]] = []
    for category_id in context.selected_category_ids:
        spec = categories_by_id.get(category_id)
        if not spec or category_id not in metrics:
            continue
        rows.append(
            [
                spec.label,
                metrics[category_id]["count"],
                metrics[category_id]["rate_with_context"],
                metrics[category_id]["rate_without_context"],
            ]
        )

    overall_rate_with = runtime.total_with / runtime.total_count if runtime.total_count else 0.0
    overall_rate_without = runtime.total_without / runtime.total_count if runtime.total_count else 0.0
    metrics["overall"] = {
        "count": runtime.total_count,
        "with_context": runtime.total_with,
        "without_context": runtime.total_without,
        "rate_with_context": round(overall_rate_with, 4),
        "rate_without_context": round(overall_rate_without, 4),
    }
    rows.append(["Overall", runtime.total_count, round(overall_rate_with, 4), round(overall_rate_without, 4)])

    payload = {
        "generated_at": utc_now_iso(),
        "benchmark_root": context.benchmark_root.as_posix(),
        "ground_truth_file": context.truth_path.as_posix(),
        "ground_truth_schema": context.truth_schema,
        "selection": context.selection_cfg,
        "coverage_by_category": context.coverage_by_category,
        "metrics": metrics,
        "sample_count": runtime.sample_count,
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

    headers = ["Category", "TP Count", "Citation@Context", "Citation@NoContext"]
    if args.table_format == "tex":
        table = render_latex_table(headers, rows, caption="Citation Success Rates")
        (output_dir / "table.tex").write_text(table, encoding="utf-8")
    else:
        table = render_markdown_table(headers, rows)
        (output_dir / "table.md").write_text(table, encoding="utf-8")

    runtime.finalize(status="interrupted" if interrupted else "completed", metrics=metrics)
    if interrupted:
        LOGGER.info("Explanation evaluation interrupted. Partial outputs written to %s", output_dir)
        return 130

    LOGGER.info("Explanation evaluation complete. Outputs written to %s", output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
