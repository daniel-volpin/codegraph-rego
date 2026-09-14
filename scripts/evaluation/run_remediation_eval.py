"""
Run remediation success evaluation using the same apply/verify flow as the API.
"""

from __future__ import annotations

import argparse
import logging
import random
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from codegraph.evaluation.pipeline import (  # noqa: E402
    collect_category_false_positive_violations,
    collect_category_violations,
    group_violations_by_testcase,
    ingest_and_evaluate_subset,
    load_benchmark_evaluation_context,
    staged_benchmark_workspace,
)
from codegraph.evaluation.provenance import collect_provenance, write_provenance  # noqa: E402
from codegraph.evaluation.remediation_runtime import (  # noqa: E402
    RemediationRuntime,
    build_agentic_outcome_summary,
    build_agentic_remediation_result,
    build_metrics_payload,
    build_remediation_result,
    build_skipped_result,
    write_final_artifacts,
)
from codegraph.remediation.orchestration import apply_remediation  # noqa: E402
from codegraph.telemetry import configure_telemetry, get_tracer, install_log_correlation  # noqa: E402

LOGGER = logging.getLogger("codegraph.eval.remediation")


def _rebase_method_key(method_key: str, prefix: str) -> str:
    """Rebase both the leading path and the embedded #file: path onto work_root.

    parse_method_selector's canonical_key is everything after the method_key's
    first "#" (the #file:<path> segment onward), matched directly against the
    freshly re-parsed method.source_key -- so #file:<path> must carry the same
    prefix as the leading path, or the two diverge and selector matching fails.
    """
    head, tail = method_key.split(":", 1)
    tail = tail.replace("#file:", f"#file:{prefix}/", 1)
    return f"{head}:{prefix}/{tail}"


def _rebase_for_agentic_workspace(violation: dict[str, Any], java_relative_root: str) -> dict[str, Any]:
    """Rebase method_key/file_path onto work_root, where the staged pom.xml lives."""
    rebased = dict(violation)
    prefix = java_relative_root.rstrip("/")

    method_key = violation.get("method_key")
    if isinstance(method_key, str) and ":" in method_key:
        rebased["method_key"] = _rebase_method_key(method_key, prefix)

    evidence = violation.get("evidence")
    if isinstance(evidence, dict):
        evidence = dict(evidence)
        evidence_method_key = evidence.get("method_key")
        if isinstance(evidence_method_key, str) and ":" in evidence_method_key:
            evidence["method_key"] = _rebase_method_key(evidence_method_key, prefix)
        evidence_file_path = evidence.get("file_path")
        if isinstance(evidence_file_path, str) and evidence_file_path:
            evidence["file_path"] = f"{prefix}/{evidence_file_path}"
        rebased["evidence"] = evidence

    file_path = violation.get("file_path")
    if isinstance(file_path, str) and file_path:
        rebased["file_path"] = f"{prefix}/{file_path}"

    return rebased


def _process_case(
    violation: dict[str, Any],
    *,
    args: argparse.Namespace,
    context: Any,
    workspace: Any,
    runtime: RemediationRuntime,
    tracer: Any,
    lock: threading.Lock,
) -> dict[str, Any]:
    with tracer.start_as_current_span("benchmark.case") as case_span:
        case_id, case_dir = runtime.prepare_case(violation)
        violation_id = violation.get("violation_id")
        evidence = violation.get("evidence") or {}
        method_key = violation.get("method_key") or evidence.get("method_key")
        target_method = violation.get("target_method")
        file_path = evidence.get("file_path") or violation.get("file_path")
        case_span.set_attribute("case_id", str(case_id or ""))
        case_span.set_attribute("violation_id", str(violation_id or ""))
        case_span.set_attribute("method_key", str(method_key or ""))
        case_span.set_attribute("target_method", str(target_method or ""))
        case_span.set_attribute("category", str(violation.get("category") or ""))
        rule_id = violation.get("rule_id") or (violation.get("control_metadata") or {}).get("rule_id") or ""
        case_span.set_attribute("rule_id", str(rule_id))

        if not violation_id or not method_key or not file_path:
            result = build_skipped_result(violation=violation, case_id=case_id, error="missing_violation_fields")
            case_span.set_attribute("final_status", "SKIPPED")
            with lock:
                runtime.record_case(apply_result=result, result=result)
            return result

        if args.mode == "agentic":
            from codegraph.remediation.orchestration import run_agentic_remediation
            java_relative_root = context.selection_cfg["java_relative_root"]
            agentic_violation = _rebase_for_agentic_workspace(violation, java_relative_root)
            apply_result = run_agentic_remediation(
                agentic_violation,
                workspace_root=workspace.work_root,
                max_turns=max(4, args.max_attempts * 3),
            )
            result = build_agentic_remediation_result(
                violation=violation,
                apply_result=apply_result,
                case_id=case_id,
                ground_truth_label=bool(violation.get("ground_truth_label", True)),
            )
        else:
            apply_result = apply_remediation(
                str(violation_id),
                method_key=str(method_key),
                file_path=str(file_path),
                mode=args.mode,
                max_attempts=args.max_attempts,
                raw_capture_dir=case_dir.as_posix(),
                build_command=args.build_command or context.selection_cfg.get("build_command"),
            )
            result = build_remediation_result(violation=violation, apply_result=apply_result, case_id=case_id)

        case_span.set_attribute("final_status", str(apply_result.get("status") or ""))
        with lock:
            runtime.record_case(apply_result=apply_result, result=result)
        return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run remediation success evaluation.")
    parser.add_argument(
        "--config",
        default="configs/benchmark/remediation_hash_smoke.json",
        help="Benchmark selection config JSON (default: %(default)s)",
    )
    parser.add_argument(
        "--categories",
        default=None,
        help=(
            "Comma-separated category ids to evaluate, restricting this run to one "
            "policy group. A failure is re-run for that group alone instead of the "
            "whole sample. Merge group outputs with compose_agentic_eval.py."
        ),
    )
    parser.add_argument(
        "--mapping",
        default="configs/benchmark/policy_registry.json",
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
        choices=["dry_run", "apply", "agentic"],
        default="dry_run",
        help="Remediation execution mode: dry_run, apply, or agentic (default: %(default)s)",
    )
    parser.add_argument(
        "--reset-neo4j",
        action="store_true",
        help="Clear Neo4j before ingesting benchmark subset",
    )
    parser.add_argument(
        "--parallel",
        type=int,
        default=1,
        help="Concurrent cases (agentic mode only; bounded by LLM_MAX_CONCURRENT_REQUESTS anyway; default: %(default)s)",
    )
    return parser.parse_args()


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s [%(otel_trace_id)s/%(otel_span_id)s] %(message)s",
    )
    configure_telemetry()
    install_log_correlation()
    tracer = get_tracer("codegraph.benchmark.remediation")
    args = parse_args()

    context = load_benchmark_evaluation_context(Path(args.config), Path(args.mapping))

    requested_groups = [part.strip() for part in (args.categories or "").split(",") if part.strip()]
    if requested_groups:
        unknown = sorted(set(requested_groups) - set(context.categories_by_id))
        if unknown:
            LOGGER.error("Unknown category ids: %s", ", ".join(unknown))
            return 1
        context.selected_category_ids[:] = [
            category_id for category_id in context.selected_category_ids if category_id in requested_groups
        ]
        LOGGER.info("Restricted to policy group(s): %s", ", ".join(context.selected_category_ids))

    sampled_by_category = context.selection.selected_by_category
    selected_ids = sorted(
        {
            record.testcase_id
            for category_id in context.selected_category_ids
            for record in sampled_by_category.get(category_id, [])
        }
    )

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    from codegraph.config import settings as _provenance_settings  # noqa: PLC0415
    provenance = collect_provenance(
        eval_kind="remediation",
        config_path=args.config,
        output_dir=output_dir,
        seed=args.seed,
        llm={
            "model": getattr(_provenance_settings, "llm_model", None),
            "remediation_model": getattr(_provenance_settings, "remediation_llm_model", None) or None,
            "temperature": getattr(_provenance_settings, "remediation_llm_temperature", None),
            "max_tokens": getattr(_provenance_settings, "remediation_llm_max_tokens", None),
        },
        extra={
            "mapping_path": str(args.mapping),
            "table_format": args.table_format,
            "mode": args.mode,
            "max_attempts": args.max_attempts,
            "sample_size": args.sample_size,
            "reset_neo4j": bool(args.reset_neo4j),
            "build_command": args.build_command or "",
            "parallel": args.parallel,
        },
    )
    write_provenance(provenance, output_dir)

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
    from codegraph.config import settings as _settings  # noqa: PLC0415

    completed = False
    with tracer.start_as_current_span("benchmark.run") as run_span:
        run_span.set_attribute("config_name", str(Path(args.config).stem))
        run_span.set_attribute("mode", args.mode)
        run_span.set_attribute("max_attempts", args.max_attempts)
        run_span.set_attribute("sample_size", args.sample_size)
        run_span.set_attribute("seed", args.seed)
        run_span.set_attribute("category_ids", str(context.selected_category_ids))
        run_span.set_attribute("model", str(getattr(_settings, "llm_model", "")))
        run_span.set_attribute("remediation_model", str(getattr(_settings, "remediation_llm_model", "") or ""))
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
                    run_span.set_attribute("final_status", "eval_error")
                    return 1
                violations = eval_result.get("violations") or []

                violations_by_testcase = group_violations_by_testcase(violations)
                category_violations_by_id = collect_category_violations(
                    selected_category_ids=context.selected_category_ids,
                    categories_by_id=context.categories_by_id,
                    selection=context.selection,
                    violations_by_testcase=violations_by_testcase,
                )
                category_fp_violations_by_id: dict[str, list[dict[str, Any]]] = {}
                if args.mode == "agentic":
                    category_fp_violations_by_id = collect_category_false_positive_violations(
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
                        candidate["ground_truth_label"] = True
                        candidates.append(candidate)
                    for violation in category_fp_violations_by_id.get(category_id, []):
                        candidate = dict(violation)
                        candidate["category"] = spec.label
                        candidate["ground_truth_label"] = False
                        candidates.append(candidate)
                if not candidates:
                    LOGGER.warning("No candidate violations found for remediation evaluation.")
                    run_span.set_attribute("final_status", "no_candidates")
                    return 1

                rng = random.Random(args.seed)
                if len(candidates) > args.sample_size:
                    candidates = rng.sample(candidates, k=args.sample_size)

                results: list[dict[str, Any]] = []
                runtime.begin(total_cases=len(candidates))
                lock = threading.Lock()
                case_kwargs = {
                    "args": args,
                    "context": context,
                    "workspace": workspace,
                    "runtime": runtime,
                    "tracer": tracer,
                    "lock": lock,
                }
                if args.mode == "agentic" and args.parallel > 1:
                    with ThreadPoolExecutor(max_workers=args.parallel) as pool:
                        futures = [pool.submit(_process_case, violation, **case_kwargs) for violation in candidates]
                        for future in futures:
                            results.append(future.result())
                else:
                    for violation in candidates:
                        results.append(_process_case(violation, **case_kwargs))

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
            if args.mode == "agentic":
                metrics["agentic_outcomes"] = build_agentic_outcome_summary(results)
            write_final_artifacts(output_dir, metrics, table_format=args.table_format)
            run_span.set_attribute("total_cases", len(results))
            run_span.set_attribute("final_status", "completed")
            runtime.finalize(status="completed")
            completed = True
        finally:
            if not completed:
                run_span.set_attribute("final_status", "failed")
                runtime.finalize(status="failed")

    LOGGER.info("Remediation evaluation complete. Outputs written to %s", output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
