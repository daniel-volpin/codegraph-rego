"""Loader and file-level eval harness for the OWASP Benchmark v1.2.

This evaluator is the **F10-isolated** counterpart to the existing full
pipeline (``run_benchmark_eval.py``). It measures the contribution of
the F10 lexical anchoring step on the OWASP test corpus *without*
graph context, Neo4j, or LLM-driven explanations — so it is
reproducible inside CI / local environments and quantifies F10's
marginal value on a real-but-synthetic SAST benchmark.

The full-pipeline thesis-final numbers are qualified evidence that does not
reproduce on the current baseline; see docs/thesis_context.md for the figure
and REPRODUCIBILITY.md for the current one. They reflect the combined
contribution of F10 + graph context + helper summaries. The
delta between pre_f10 and post_f10 here lower-bounds F10's
file-level effect; the production pipeline only adds signal.

Methodology and literature framing live in
``docs/lexical_anchoring_methodology.md``.
"""

from __future__ import annotations

import multiprocessing as mp
import os
from collections.abc import Mapping, Sequence
from pathlib import Path

from baselines.semgrep.runner import SemgrepRunResult
from codegraph.evaluation.lexical_noise_eval import (
    METHODS,
    DetectionResult,
    MethodMetrics,
    PairedComparison,
    _build_minimal_bundle,
    _extract_target_method,
    _fired_ids,
)
from codegraph.evaluation.owasp_lexical_formatter import format_markdown_summary
from codegraph.evaluation.owasp_lexical_models import (
    CWE_TO_ISO,
    SUPPORTED_CWES,
    OwaspCase,
    OwaspCaseRow,
    OwaspEvalReport,
    load_owasp_cases,
    owasp_corpus_sha,
    owasp_paths,
    resolve_owasp_root,
)
from codegraph.evaluation.uncertainty import (
    bootstrap_paired_delta_ci,
    paired_classifier_mcnemar,
)
from codegraph.policy.runtime.opa import evaluate_bundle

__all__ = [
    "CWE_TO_ISO",
    "SUPPORTED_CWES",
    "OwaspCase",
    "OwaspCaseRow",
    "OwaspEvalReport",
    "evaluate_owasp",
    "format_markdown_summary",
    "load_owasp_cases",
    "owasp_corpus_sha",
    "owasp_paths",
    "resolve_owasp_root",
]


# Per-case detection


def _detect_via_semgrep_for_owasp(
    case: OwaspCase, semgrep_findings_by_file: Mapping[str, Sequence[str]]
) -> DetectionResult:
    """Resolve the per-case semgrep verdict from a pre-aggregated index."""
    cg_ids = set(semgrep_findings_by_file.get(case.java_path.name, ()))
    fired = tuple(sorted(cg_ids))
    target_fired = case.target_violation_id in cg_ids
    return DetectionResult(
        case_id=case.test_name,
        method="semgrep",
        fired_violation_ids=fired,
        target_fired=target_fired,
    )


_OWASP_FQN_PACKAGE = "org.owasp.benchmark.testcode"


def _worker_run(
    payload: tuple[str, str, str, str],
) -> tuple[str, bool, tuple[str, ...], bool, tuple[str, ...]]:
    """Module-level worker for ``multiprocessing.Pool``.

    Input  : ``(test_name, java_path, target_violation_id, rel_path)``.
    Output : ``(test_name, pre_target_fired, pre_fired, post_target_fired, post_fired)``.

    Defined at module scope so it pickles cleanly across worker processes.
    """

    test_name, java_path_str, target_violation_id, rel_path = payload
    source = Path(java_path_str).read_text(encoding="utf-8")
    target_method = _extract_target_method(test_name, source, package=_OWASP_FQN_PACKAGE)

    pre_bundle = _build_minimal_bundle(source, file_path=rel_path, target_method=target_method, f10_active=False)
    pre_violations = evaluate_bundle(pre_bundle)
    pre_fired = _fired_ids(pre_violations)

    post_bundle = _build_minimal_bundle(source, file_path=rel_path, target_method=target_method, f10_active=True)
    post_violations = evaluate_bundle(post_bundle)
    post_fired = _fired_ids(post_violations)

    return (
        test_name,
        target_violation_id in set(pre_fired),
        pre_fired,
        target_violation_id in set(post_fired),
        post_fired,
    )


def _aggregate_metrics(
    rows: Sequence[OwaspCaseRow],
    *,
    n_resamples: int,
    seed: int,
) -> dict[str, MethodMetrics]:
    out: dict[str, MethodMetrics] = {}
    for method in METHODS:
        outcomes = [(row.by_method[method].target_fired, row.case.real_vulnerability) for row in rows]
        out[method] = MethodMetrics.from_outcomes(method, outcomes, n_resamples=n_resamples, seed=seed)
    return out


def evaluate_owasp(
    cases: Sequence[OwaspCase],
    *,
    java_root: Path,
    semgrep_result: SemgrepRunResult,
    n_resamples: int = 2000,
    seed: int = 0,
    workers: int | None = None,
    benchmark_id: str = "owasp_benchmark_v1.2_file_level",
) -> OwaspEvalReport:
    """Run the file-level eval. Uses a process pool when ``workers`` > 1."""

    semgrep_idx: dict[str, list[str]] = {}
    for finding in semgrep_result.findings:
        cg_id = finding.codegraph_violation_id
        if not cg_id:
            continue
        semgrep_idx.setdefault(Path(finding.file_path).name, []).append(cg_id)

    payloads: list[tuple[str, str, str, str]] = []
    for case in cases:
        try:
            rel = str(case.java_path.relative_to(java_root))
        except ValueError:
            rel = case.java_path.name
        payloads.append((case.test_name, str(case.java_path), case.target_violation_id, rel))

    if workers is None:
        workers = max(1, (os.cpu_count() or 1) - 1)

    if workers > 1 and len(payloads) > workers:
        with mp.Pool(processes=workers) as pool:
            results = pool.map(_worker_run, payloads)
    else:
        results = [_worker_run(p) for p in payloads]

    rows: list[OwaspCaseRow] = []
    case_index = {c.test_name: c for c in cases}
    for test_name, pre_fired_target, pre_fired, post_fired_target, post_fired in results:
        case = case_index[test_name]
        smg = _detect_via_semgrep_for_owasp(case, semgrep_idx)
        rows.append(
            OwaspCaseRow(
                case=case,
                by_method={
                    "pre_f10": DetectionResult(
                        case_id=test_name,
                        method="pre_f10",
                        fired_violation_ids=pre_fired,
                        target_fired=pre_fired_target,
                    ),
                    "post_f10": DetectionResult(
                        case_id=test_name,
                        method="post_f10",
                        fired_violation_ids=post_fired,
                        target_fired=post_fired_target,
                    ),
                    "semgrep": smg,
                },
            )
        )

    overall = _aggregate_metrics(rows, n_resamples=n_resamples, seed=seed)
    per_cwe: dict[str, Mapping[str, MethodMetrics]] = {}
    for cwe in sorted({row.case.cwe for row in rows}):
        cwe_rows = [r for r in rows if r.case.cwe == cwe]
        per_cwe[cwe] = _aggregate_metrics(cwe_rows, n_resamples=n_resamples, seed=seed)

    paired = _compute_owasp_paired(rows, n_resamples=n_resamples, seed=seed)

    return OwaspEvalReport(
        benchmark_id=benchmark_id,
        n_cases=len(rows),
        cwes_evaluated=tuple(sorted({c.cwe for c in cases})),
        paired=paired,
        rows=tuple(rows),
        overall=overall,
        per_cwe=per_cwe,
    )


def _compute_owasp_paired(
    rows: Sequence[OwaspCaseRow],
    *,
    n_resamples: int,
    seed: int,
) -> tuple[PairedComparison, ...]:
    """Paired tests for the OWASP F10 contract: pre_f10 vs post_f10.

    Three scopes: overall, fp_class (NEG cases only), and one per CWE
    family. The expected b = c = 0 across the whole corpus is the
    regression-safety claim — McNemar will report ``test_defined=False``
    on cases with no disagreements, which is the right outcome.
    """

    def triples(rs: Sequence[OwaspCaseRow]) -> list[tuple[bool, bool, bool]]:
        return [
            (
                r.by_method["pre_f10"].target_fired,
                r.by_method["post_f10"].target_fired,
                r.case.real_vulnerability,
            )
            for r in rs
        ]

    all_paired = triples(rows)
    out: list[PairedComparison] = []
    for scope, restrict in (("overall", "all"), ("fp_class", "fp_class")):
        out.append(
            PairedComparison(
                method_a="pre_f10",
                method_b="post_f10",
                scope=scope,
                mcnemar=paired_classifier_mcnemar(all_paired, restrict_to=restrict),
                delta_fpr=bootstrap_paired_delta_ci(all_paired, metric="fpr", n_resamples=n_resamples, seed=seed),
                delta_fnr=bootstrap_paired_delta_ci(all_paired, metric="fnr", n_resamples=n_resamples, seed=seed),
            )
        )
    for cwe in sorted({r.case.cwe for r in rows}, key=lambda c: int(c)):
        cwe_paired = triples([r for r in rows if r.case.cwe == cwe])
        out.append(
            PairedComparison(
                method_a="pre_f10",
                method_b="post_f10",
                scope=f"cwe:{cwe}",
                mcnemar=paired_classifier_mcnemar(cwe_paired),
                delta_fpr=bootstrap_paired_delta_ci(cwe_paired, metric="fpr", n_resamples=n_resamples, seed=seed),
                delta_fnr=bootstrap_paired_delta_ci(cwe_paired, metric="fnr", n_resamples=n_resamples, seed=seed),
            )
        )
    return tuple(out)
