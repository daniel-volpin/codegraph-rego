"""Loader and file-level eval harness for the OWASP Benchmark v1.2.

This evaluator is the **F10-isolated** counterpart to the existing full
pipeline (``run_benchmark_eval.py``). It measures the contribution of
the F10 lexical anchoring step on the OWASP test corpus *without*
graph context, Neo4j, or LLM-driven explanations — so it is
reproducible inside CI / local environments and quantifies F10's
marginal value on a real-but-synthetic SAST benchmark.

The full-pipeline thesis-final numbers (P=R=F1=0.953) reflect the
combined contribution of F10 + graph context + helper summaries. The
delta between pre_f10 and post_f10 here lower-bounds F10's
file-level effect; the production pipeline only adds signal.

Methodology and literature framing live in
``docs/lexical_anchoring_methodology.md``.
"""

from __future__ import annotations

import csv
import multiprocessing as mp
import os
import random
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple

from baselines.semgrep.runner import SemgrepRunResult
from codegraph.evaluation.lexical_noise_eval import (
    METHODS,
    DetectionResult,
    MethodMetrics,
    _build_minimal_bundle,
    _extract_target_method,
    _fired_ids,
)
from codegraph.policy.runtime.opa import evaluate_bundle


CWE_TO_ISO: Dict[str, str] = {
    "22": "ISO-A.8-PATH-TRAVERSAL",
    "78": "ISO-A.8-CMD-INJECTION",
    "89": "ISO-A.8-SQL-INJECTION",
    "90": "ISO-A.8-LDAP-INJECTION",
    "327": "ISO-A.10-WEAK-CRYPTO",
    "328": "ISO-A.10-WEAK-HASH",
    "330": "ISO-A.10-WEAK-RANDOM",
    "643": "ISO-A.8-XPATH-INJECTION",
}
SUPPORTED_CWES: frozenset[str] = frozenset(CWE_TO_ISO.keys())


_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_OWASP_CACHE = _PROJECT_ROOT / ".benchmark_cache" / "owasp-benchmark"
_FALLBACK_OWASP_TMP = Path("/tmp/owasp-benchmark")
_OWASP_GROUND_TRUTH_BASENAME = "expectedresults-1.2.csv"


def resolve_owasp_root(explicit: Path | None = None) -> Path | None:
    """Locate an OWASP Benchmark v1.2 checkout.

    Resolution order: ``explicit`` arg → ``$OWASP_BENCHMARK_ROOT`` →
    ``.benchmark_cache/owasp-benchmark/`` → ``/tmp/owasp-benchmark/``.
    Returns the first candidate whose ``expectedresults-1.2.csv`` exists,
    or ``None`` if no candidate is usable.
    """

    candidates: list[Path] = []
    if explicit is not None:
        candidates.append(explicit)
    env = os.environ.get("OWASP_BENCHMARK_ROOT")
    if env:
        candidates.append(Path(env))
    candidates.append(_DEFAULT_OWASP_CACHE)
    candidates.append(_FALLBACK_OWASP_TMP)
    for c in candidates:
        if c.is_dir() and (c / _OWASP_GROUND_TRUTH_BASENAME).is_file():
            return c
    return None


def owasp_paths(owasp_root: Path) -> tuple[Path, Path]:
    """Return ``(ground_truth_csv, java_testcode_root)`` under ``owasp_root``."""

    csv_path = owasp_root / _OWASP_GROUND_TRUTH_BASENAME
    java_root = (
        owasp_root / "src" / "main" / "java"
        / "org" / "owasp" / "benchmark" / "testcode"
    )
    return csv_path, java_root


@dataclass(frozen=True)
class OwaspCase:
    test_name: str  # e.g. BenchmarkTest00001
    category: str  # OWASP-internal category, e.g. "pathtraver"
    real_vulnerability: bool  # ground truth: contains a real instance of the CWE
    cwe: str  # numeric, e.g. "22"
    java_path: Path  # absolute path to the .java file

    @property
    def target_violation_id(self) -> str:
        return CWE_TO_ISO[self.cwe]


@dataclass(frozen=True)
class OwaspCaseRow:
    case: OwaspCase
    by_method: Mapping[str, DetectionResult]


@dataclass(frozen=True)
class OwaspEvalReport:
    benchmark_id: str
    n_cases: int
    cwes_evaluated: tuple[str, ...]
    rows: tuple[OwaspCaseRow, ...]
    overall: Mapping[str, MethodMetrics]
    per_cwe: Mapping[str, Mapping[str, MethodMetrics]]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "benchmark_id": self.benchmark_id,
            "n_cases": self.n_cases,
            "cwes_evaluated": list(self.cwes_evaluated),
            "overall": {name: _metrics_to_dict(m) for name, m in self.overall.items()},
            "per_cwe": {
                cwe: {name: _metrics_to_dict(m) for name, m in inner.items()}
                for cwe, inner in self.per_cwe.items()
            },
            "rows": [
                {
                    "test_name": row.case.test_name,
                    "cwe": row.case.cwe,
                    "category": row.case.category,
                    "real_vulnerability": row.case.real_vulnerability,
                    "target_violation_id": row.case.target_violation_id,
                    "by_method": {
                        method: {
                            "fired_violation_ids": list(
                                row.by_method[method].fired_violation_ids
                            ),
                            "target_fired": row.by_method[method].target_fired,
                        }
                        for method in METHODS
                        if method in row.by_method
                    },
                }
                for row in self.rows
            ],
        }


def _metrics_to_dict(m: MethodMetrics) -> Dict[str, Any]:
    payload = {k: v for k, v in asdict(m).items() if k != "bootstrap"}
    payload["bootstrap"] = dict(m.bootstrap)
    return payload


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------


def load_owasp_cases(
    csv_path: Path,
    java_root: Path,
    *,
    cwes: Iterable[str] | None = None,
    limit_per_cwe: int | None = None,
    seed: int = 0,
) -> List[OwaspCase]:
    """Load the OWASP expected-results CSV, restricted to CodeGraph CWEs.

    Each surviving row is resolved against ``java_root`` (the directory
    holding the ``BenchmarkTestNNNNN.java`` files). Missing source files
    are skipped silently — useful when working from a partial checkout.

    ``limit_per_cwe`` stratifies the sample so each CWE gets the same
    cap, preserving the real/false ratio within the CWE via a seeded
    shuffle. This keeps bootstrap CIs comparable across CWEs.
    """

    target_cwes = frozenset(cwes) if cwes is not None else SUPPORTED_CWES
    if not target_cwes.issubset(SUPPORTED_CWES):
        unknown = target_cwes - SUPPORTED_CWES
        raise ValueError(f"Unsupported CWEs requested: {sorted(unknown)}")

    by_cwe: Dict[str, List[OwaspCase]] = {cwe: [] for cwe in target_cwes}
    with csv_path.open("r", encoding="utf-8") as handle:
        reader = csv.reader(handle)
        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            if len(row) < 4:
                continue
            test_name, category, real_str, cwe = (
                row[0].strip(),
                row[1].strip(),
                row[2].strip().lower(),
                row[3].strip(),
            )
            if cwe not in target_cwes:
                continue
            java_path = java_root / f"{test_name}.java"
            if not java_path.is_file():
                continue
            by_cwe[cwe].append(
                OwaspCase(
                    test_name=test_name,
                    category=category,
                    real_vulnerability=real_str == "true",
                    cwe=cwe,
                    java_path=java_path,
                )
            )

    rng = random.Random(seed)
    flat: List[OwaspCase] = []
    for cwe in sorted(by_cwe.keys()):
        cases = by_cwe[cwe]
        rng.shuffle(cases)
        if limit_per_cwe is not None:
            cases = cases[:limit_per_cwe]
        flat.extend(cases)
    return flat


# ---------------------------------------------------------------------------
# Per-case detection
# ---------------------------------------------------------------------------


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
    payload: Tuple[str, str, str, str],
) -> Tuple[str, bool, tuple[str, ...], bool, tuple[str, ...]]:
    """Module-level worker for ``multiprocessing.Pool``.

    Input  : ``(test_name, java_path, target_violation_id, rel_path)``.
    Output : ``(test_name, pre_target_fired, pre_fired, post_target_fired, post_fired)``.

    Defined at module scope so it pickles cleanly across worker processes.
    """

    test_name, java_path_str, target_violation_id, rel_path = payload
    source = Path(java_path_str).read_text(encoding="utf-8")
    target_method = _extract_target_method(
        test_name, source, package=_OWASP_FQN_PACKAGE
    )

    pre_bundle = _build_minimal_bundle(
        source, file_path=rel_path, target_method=target_method, f10_active=False
    )
    pre_violations = evaluate_bundle(pre_bundle)
    pre_fired = _fired_ids(pre_violations)

    post_bundle = _build_minimal_bundle(
        source, file_path=rel_path, target_method=target_method, f10_active=True
    )
    post_violations = evaluate_bundle(post_bundle)
    post_fired = _fired_ids(post_violations)

    return (
        test_name,
        target_violation_id in set(pre_fired),
        pre_fired,
        target_violation_id in set(post_fired),
        post_fired,
    )


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------


def _aggregate_metrics(
    rows: Sequence[OwaspCaseRow],
    *,
    n_resamples: int,
    seed: int,
) -> Dict[str, MethodMetrics]:
    out: Dict[str, MethodMetrics] = {}
    for method in METHODS:
        outcomes = [
            (row.by_method[method].target_fired, row.case.real_vulnerability)
            for row in rows
        ]
        out[method] = MethodMetrics.from_outcomes(
            method, outcomes, n_resamples=n_resamples, seed=seed
        )
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

    semgrep_idx: Dict[str, List[str]] = {}
    for finding in semgrep_result.findings:
        cg_id = finding.codegraph_violation_id
        if not cg_id:
            continue
        semgrep_idx.setdefault(Path(finding.file_path).name, []).append(cg_id)

    payloads: List[Tuple[str, str, str, str]] = []
    for case in cases:
        try:
            rel = str(case.java_path.relative_to(java_root))
        except ValueError:
            rel = case.java_path.name
        payloads.append(
            (case.test_name, str(case.java_path), case.target_violation_id, rel)
        )

    if workers is None:
        workers = max(1, (os.cpu_count() or 1) - 1)

    if workers > 1 and len(payloads) > workers:
        with mp.Pool(processes=workers) as pool:
            results = pool.map(_worker_run, payloads)
    else:
        results = [_worker_run(p) for p in payloads]

    rows: List[OwaspCaseRow] = []
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
    per_cwe: Dict[str, Mapping[str, MethodMetrics]] = {}
    for cwe in sorted({row.case.cwe for row in rows}):
        cwe_rows = [r for r in rows if r.case.cwe == cwe]
        per_cwe[cwe] = _aggregate_metrics(cwe_rows, n_resamples=n_resamples, seed=seed)

    return OwaspEvalReport(
        benchmark_id=benchmark_id,
        n_cases=len(rows),
        cwes_evaluated=tuple(sorted({c.cwe for c in cases})),
        rows=tuple(rows),
        overall=overall,
        per_cwe=per_cwe,
    )


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def _metrics_cells(m: MethodMetrics) -> str:
    """Render the numeric / CI cells (no leading or trailing pipe)."""

    b = m.bootstrap
    p_ci = b.get("precision", {})
    r_ci = b.get("recall", {})
    f_ci = b.get("f1", {})
    return (
        " {tp} | {fp} | {tn} | {fn} | {p:.3f} | {r:.3f} | {f:.3f} "
        "| [{p_lo:.3f}, {p_hi:.3f}] | [{r_lo:.3f}, {r_hi:.3f}] | [{f_lo:.3f}, {f_hi:.3f}] "
    ).format(
        tp=m.tp,
        fp=m.fp,
        tn=m.tn,
        fn=m.fn,
        p=m.precision,
        r=m.recall,
        f=m.f1,
        p_lo=p_ci.get("ci_low", 0.0),
        p_hi=p_ci.get("ci_high", 0.0),
        r_lo=r_ci.get("ci_low", 0.0),
        r_hi=r_ci.get("ci_high", 0.0),
        f_lo=f_ci.get("ci_low", 0.0),
        f_hi=f_ci.get("ci_high", 0.0),
    )


def format_markdown_summary(report: OwaspEvalReport) -> str:
    """Markdown summary table — overall + per-CWE breakdown."""

    header = (
        f"# OWASP Benchmark v1.2 — File-Level Detection Summary "
        f"({report.benchmark_id}, n={report.n_cases})\n\n"
        "## Overall metrics\n\n"
        "| Method | TP | FP | TN | FN | Precision | Recall | F1 "
        "| P CI (95%) | R CI (95%) | F1 CI (95%) |\n"
        "|---|---:|---:|---:|---:|---:|---:|---:|---|---|---|\n"
    )
    overall_rows = "\n".join(
        f"| {name} |{_metrics_cells(report.overall[name])}|" for name in METHODS
    )

    per_cwe_header = (
        "\n\n## Per-CWE metrics\n\n"
        "| CWE | ISO target | Method | TP | FP | TN | FN | Precision | Recall | F1 "
        "| P CI (95%) | R CI (95%) | F1 CI (95%) |\n"
        "|---|---|---|---:|---:|---:|---:|---:|---:|---:|---|---|---|\n"
    )
    per_cwe_rows = []
    for cwe in sorted(report.per_cwe.keys(), key=lambda c: int(c)):
        iso = CWE_TO_ISO.get(cwe, "?")
        for method in METHODS:
            cells = _metrics_cells(report.per_cwe[cwe][method])
            per_cwe_rows.append(f"| CWE-{cwe} | {iso} | {method} |{cells}|")

    return (
        header
        + overall_rows
        + per_cwe_header
        + "\n".join(per_cwe_rows)
        + "\n"
    )
