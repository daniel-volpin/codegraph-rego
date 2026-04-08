"""
Shadow comparison evaluation: deterministic vs LLM remediation.

Runs both paths on the same benchmark violations and emits per-case
and aggregate comparison artifacts.  Does not alter the live
remediation flow.

Usage::

    .venv/bin/python run_comparison_eval.py \\
        --config configs/benchmark/remediation_hash_smoke.json \\
        --output-dir outputs/comparison_eval \\
        --sample-size 10

Artifacts written::

    outputs/comparison_eval/
        comparison_summary.json
        comparison_summary.md
        cases/<case_id>/
            comparison.json
            deterministic_outcome.json
            llm_outcome.json
"""

from __future__ import annotations

import argparse
import logging
import random
from pathlib import Path
from typing import Any

from codegraph.evaluation.io import write_json
from codegraph.evaluation.pipeline import (
    collect_category_violations,
    group_violations_by_testcase,
    ingest_and_evaluate_subset,
    load_benchmark_evaluation_context,
    staged_benchmark_workspace,
)
from codegraph.evaluation.remediation_runtime import build_case_id
from codegraph.remediation.comparison import (
    ComparisonResult,
    build_comparison_summary,
    build_deterministic_outcome,
    build_llm_outcome,
    compare_remediation,
    render_comparison_summary_markdown,
)
from codegraph.remediation.orchestration import apply_remediation
from codegraph.remediation.dossier import build_dossier
from codegraph.remediation.ranking import (
    RankingResult,
    build_ranking_summary,
    rank_candidates,
)

LOGGER = logging.getLogger("codegraph.eval.comparison")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Shadow comparison: deterministic vs LLM remediation.",
    )
    parser.add_argument(
        "--config",
        default="configs/benchmark/remediation_hash_smoke.json",
        help="Benchmark selection config JSON (default: %(default)s)",
    )
    parser.add_argument(
        "--mapping",
        default="configs/benchmark/policy_registry.json",
        help="Control/CWE/Rego mapping JSON (default: %(default)s)",
    )
    parser.add_argument(
        "--output-dir",
        default="outputs/comparison_eval",
        help="Output directory (default: %(default)s)",
    )
    parser.add_argument(
        "--sample-size",
        type=int,
        default=10,
        help="Number of violations to compare (default: %(default)s)",
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
        help="Clear Neo4j before ingesting benchmark subset",
    )
    parser.add_argument(
        "--max-attempts",
        type=int,
        default=2,
        help="Maximum LLM remediation attempts per violation (default: %(default)s)",
    )
    parser.add_argument(
        "--mode",
        choices=["dry_run", "apply"],
        default="dry_run",
        help="LLM remediation execution mode (default: %(default)s)",
    )
    return parser.parse_args()


def _extract_source_lines(violation: dict[str, Any]) -> list[str]:
    """Extract method source lines from violation evidence."""
    evidence = violation.get("evidence") or {}
    source_code = evidence.get("source_code") or ""
    if isinstance(source_code, str) and source_code.strip():
        return source_code.splitlines()
    return []


def _build_violation_context(violation: dict[str, Any]) -> dict[str, Any]:
    """Build a violation context dict from a raw violation record."""
    evidence = violation.get("evidence") or {}
    return {
        "violation_id": violation.get("violation_id"),
        "rule_id": violation.get("rule_id"),
        "file_path": evidence.get("file_path") or violation.get("file_path"),
        "target_method": violation.get("target_method"),
        "evidence": evidence,
    }


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    args = parse_args()

    context = load_benchmark_evaluation_context(Path(args.config), Path(args.mapping))
    selected_ids = context.selection.selected_testcase_ids

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    cases_dir = output_dir / "cases"
    cases_dir.mkdir(parents=True, exist_ok=True)

    LOGGER.info("Loaded benchmark context, %d selected testcases", len(selected_ids))

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

            candidates: list[dict[str, Any]] = []
            for category_id in context.selected_category_ids:
                spec = context.categories_by_id.get(category_id)
                if not spec:
                    continue
                for violation in category_violations_by_id.get(category_id, []):
                    candidate = dict(violation)
                    candidate["category"] = spec.label
                    candidates.append(candidate)

            if not candidates:
                LOGGER.warning("No candidate violations found for comparison.")
                return 1

            rng = random.Random(args.seed)
            if len(candidates) > args.sample_size:
                candidates = rng.sample(candidates, k=args.sample_size)

            LOGGER.info("Comparing %d violations", len(candidates))

            comparison_results: list[ComparisonResult] = []
            ranking_results: list[RankingResult] = []
            for i, violation in enumerate(candidates, 1):
                case_id = build_case_id(violation)
                case_dir = cases_dir / case_id
                case_dir.mkdir(parents=True, exist_ok=True)

                violation_id = violation.get("violation_id") or "unknown"
                target_method = violation.get("target_method") or ""
                evidence = violation.get("evidence") or {}
                file_path = evidence.get("file_path") or violation.get("file_path") or ""

                LOGGER.info(
                    "[%d/%d] %s %s",
                    i,
                    len(candidates),
                    violation_id,
                    target_method,
                )

                # Build context for deterministic path.
                ctx = _build_violation_context(violation)
                source_lines = _extract_source_lines(violation)

                # --- Deterministic path ---
                det_outcome = build_deterministic_outcome(ctx, source_lines)

                # --- LLM path ---
                if violation_id and target_method and file_path:
                    shadow_context = {
                        "deterministic_baseline_available": det_outcome.produced_edits,
                        "deterministic_diff_snippet": det_outcome.diff_snippet if det_outcome.produced_edits else None,
                    }
                    if not shadow_context["deterministic_diff_snippet"]:
                        del shadow_context["deterministic_diff_snippet"]

                    apply_result = apply_remediation(
                        str(violation_id),
                        target_method=str(target_method),
                        file_path=str(file_path),
                        mode=args.mode,
                        max_attempts=args.max_attempts,
                        prompt_context=shadow_context,
                    )
                else:
                    apply_result = {
                        "status": "SKIPPED",
                        "error": "missing_violation_fields",
                    }
                llm_outcome = build_llm_outcome(apply_result)

                # --- Compare ---
                comparison = compare_remediation(ctx, det_outcome, llm_outcome)
                comparison_results.append(comparison)

                # --- Rank ---
                ranking = rank_candidates(
                    violation_id=str(violation_id),
                    rule_id=str(ctx.get("rule_id") or "unknown"),
                    candidates=[det_outcome, llm_outcome],
                )
                ranking_results.append(ranking)

                # --- Build Dossier ---
                dossier = build_dossier(
                    case_id=case_id,
                    rule_id=str(ctx.get("rule_id") or "unknown"),
                    det_outcome=det_outcome,
                    llm_outcome=llm_outcome,
                    ranking=ranking,
                )

                # --- Write per-case artifacts ---
                write_json(case_dir / "comparison.json", comparison.model_dump())
                write_json(case_dir / "deterministic_outcome.json", det_outcome.model_dump())
                write_json(case_dir / "llm_outcome.json", llm_outcome.model_dump())
                write_json(case_dir / "ranking.json", ranking.model_dump())
                write_json(case_dir / "dossier.json", dossier.model_dump())

                LOGGER.info(
                    "  → %s (det=%s, llm=%s) [Ranked: %s]",
                    comparison.label.value,
                    "edits" if det_outcome.produced_edits else ("refused" if det_outcome.refused else "error"),
                    "edits" if llm_outcome.produced_edits else ("refused" if llm_outcome.refused else "error"),
                    ranking.recommended_source,
                )

        # --- Aggregate artifacts ---
        summary = build_comparison_summary(comparison_results)
        write_json(output_dir / "comparison_summary.json", summary.model_dump())

        ranking_summary = build_ranking_summary(ranking_results)
        write_json(output_dir / "ranking_summary.json", ranking_summary.model_dump())

        md = render_comparison_summary_markdown(summary)
        (output_dir / "comparison_summary.md").write_text(md, encoding="utf-8")

        LOGGER.info("Comparison complete. %d cases. Outputs: %s", summary.total_cases, output_dir)
        completed = True

    finally:
        if not completed:
            LOGGER.error("Comparison evaluation did not complete successfully.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
