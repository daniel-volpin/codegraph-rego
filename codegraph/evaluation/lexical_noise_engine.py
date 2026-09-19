from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from baselines.semgrep.runner import SemgrepRunResult
from codegraph.evaluation.lexical_noise import LexicalNoiseBenchmark
from codegraph.evaluation.lexical_noise_report_models import (
    METHODS,
    SEMGREP_REGISTRY_METHOD,
    CaseRow,
    DetectionResult,
    EvalReport,
    MethodMetrics,
    PairedComparison,
    StratumMetrics,
)
from codegraph.evaluation.uncertainty import bootstrap_paired_delta_ci, paired_classifier_mcnemar


def evaluate_benchmark_cases(
    benchmark: LexicalNoiseBenchmark,
    project_root: Path,
    semgrep_result: SemgrepRunResult,
    *,
    detect_via_opa_fn: Any,
    detect_via_semgrep_fn: Any,
    detect_via_semgrep_registry_fn: Any,
    n_resamples: int = 2000,
    seed: int = 0,
    semgrep_registry_result: SemgrepRunResult | None = None,
) -> EvalReport:
    java_root = benchmark.resolve_java_root(project_root)
    fixture_root_relative = benchmark.fixture_root_relative

    active_methods: list[str] = list(METHODS)
    if semgrep_registry_result is not None:
        active_methods.append(SEMGREP_REGISTRY_METHOD)

    rows: list[CaseRow] = []
    outcomes_by_method: dict[str, list[tuple[bool, bool]]] = {m: [] for m in active_methods}

    package_path = benchmark.package.replace(".", "/")
    for case in benchmark.cases:
        java_file = java_root / package_path / case.file_name
        source = java_file.read_text(encoding="utf-8")
        rel_path = f"{fixture_root_relative}/{benchmark.java_relative_root}/{package_path}/{case.file_name}"

        pre = detect_via_opa_fn(case, source, file_path=rel_path, f10_active=False)
        post = detect_via_opa_fn(case, source, file_path=rel_path, f10_active=True)
        smg = detect_via_semgrep_fn(case, semgrep_result)

        by_method: dict[str, DetectionResult] = {
            "pre_f10": pre,
            "post_f10": post,
            "semgrep": smg,
        }
        if semgrep_registry_result is not None:
            by_method[SEMGREP_REGISTRY_METHOD] = detect_via_semgrep_registry_fn(case, semgrep_registry_result)

        rows.append(
            CaseRow(
                case_id=case.case_id,
                file_name=case.file_name,
                fp_source=case.fp_source,
                expected=case.expected,
                target_violation_ids=case.target_violation_ids,
                by_method=by_method,
            )
        )

        label = case.expected == "positive"
        for method in active_methods:
            outcomes_by_method[method].append((by_method[method].target_fired, label))

    metrics = {
        method: MethodMetrics.from_outcomes(method, outcomes_by_method[method], n_resamples=n_resamples, seed=seed)
        for method in active_methods
    }

    per_stratum = _compute_per_stratum(rows, n_resamples=n_resamples, seed=seed)
    paired = _compute_paired_comparisons(rows, n_resamples=n_resamples, seed=seed, per_stratum=per_stratum)

    return EvalReport(
        benchmark_id=benchmark.benchmark_id,
        n_cases=len(rows),
        rows=tuple(rows),
        metrics=metrics,
        per_stratum=per_stratum,
        paired=paired,
    )


def _compute_per_stratum(
    rows: Sequence[CaseRow],
    *,
    n_resamples: int,
    seed: int,
) -> dict[str, StratumMetrics]:
    grouped: dict[str, list[CaseRow]] = {}
    for row in rows:
        grouped.setdefault(row.fp_source, []).append(row)

    active_methods: list[str] = []
    if rows:
        seen: set[str] = set()
        for method in METHODS:
            if method in rows[0].by_method:
                active_methods.append(method)
                seen.add(method)
        for method in rows[0].by_method:
            if method not in seen:
                active_methods.append(method)

    out: dict[str, StratumMetrics] = {}
    for stratum in sorted(grouped.keys()):
        s_rows = grouped[stratum]
        s_methods: dict[str, MethodMetrics] = {}
        for method in active_methods:
            outcomes = [(r.by_method[method].target_fired, r.expected == "positive") for r in s_rows]
            s_methods[method] = MethodMetrics.from_outcomes(method, outcomes, n_resamples=n_resamples, seed=seed)
        out[stratum] = StratumMetrics(
            stratum=stratum,
            n_cases=len(s_rows),
            n_positive=sum(1 for r in s_rows if r.expected == "positive"),
            n_negative=sum(1 for r in s_rows if r.expected == "negative"),
            methods=s_methods,
        )
    return out


def _paired_triples(rows: Sequence[CaseRow], method_a: str, method_b: str) -> list[tuple[bool, bool, bool]]:
    return [
        (
            row.by_method[method_a].target_fired,
            row.by_method[method_b].target_fired,
            row.expected == "positive",
        )
        for row in rows
    ]


def _compute_paired_comparisons(
    rows: Sequence[CaseRow],
    *,
    n_resamples: int,
    seed: int,
    per_stratum: Mapping[str, StratumMetrics],
) -> tuple[PairedComparison, ...]:
    method_a, method_b = "pre_f10", "post_f10"
    out: list[PairedComparison] = []

    all_paired = _paired_triples(rows, method_a, method_b)
    out.append(
        PairedComparison(
            method_a=method_a,
            method_b=method_b,
            scope="overall",
            mcnemar=paired_classifier_mcnemar(all_paired),
            delta_fpr=bootstrap_paired_delta_ci(all_paired, metric="fpr", n_resamples=n_resamples, seed=seed),
            delta_fnr=bootstrap_paired_delta_ci(all_paired, metric="fnr", n_resamples=n_resamples, seed=seed),
        )
    )
    out.append(
        PairedComparison(
            method_a=method_a,
            method_b=method_b,
            scope="fp_class",
            mcnemar=paired_classifier_mcnemar(all_paired, restrict_to="fp_class"),
            delta_fpr=bootstrap_paired_delta_ci(all_paired, metric="fpr", n_resamples=n_resamples, seed=seed),
            delta_fnr=bootstrap_paired_delta_ci(all_paired, metric="fnr", n_resamples=n_resamples, seed=seed),
        )
    )

    for stratum in sorted(per_stratum.keys()):
        s_rows = [r for r in rows if r.fp_source == stratum]
        s_paired = _paired_triples(s_rows, method_a, method_b)
        out.append(
            PairedComparison(
                method_a=method_a,
                method_b=method_b,
                scope=f"stratum:{stratum}",
                mcnemar=paired_classifier_mcnemar(s_paired),
                delta_fpr=bootstrap_paired_delta_ci(s_paired, metric="fpr", n_resamples=n_resamples, seed=seed),
                delta_fnr=bootstrap_paired_delta_ci(s_paired, metric="fnr", n_resamples=n_resamples, seed=seed),
            )
        )
    return tuple(out)
