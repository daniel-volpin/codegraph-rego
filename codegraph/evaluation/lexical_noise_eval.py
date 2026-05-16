"""Detection eval for the LexicalNoiseJava benchmark.

Runs each fixture through the OPA/Rego pipeline in two modes:

* ``pre_f10`` — ``source_code`` is the raw fixture content (comments and
  literals included), reproducing the CodeGraph behaviour before
  F10/lexical anchoring landed.
* ``post_f10`` — ``source_code`` is the substring-safe view produced by
  ``strip_java_lexical_noise(..., strip_string_literals=True)``, i.e. the
  view the OPA rules now receive in production.

The same fixtures are evaluated by SemGrep (Phase C baseline) so the
report contains a three-column comparison: pre_f10 / post_f10 / semgrep.

This eval is LLM-free and Neo4j-free: it constructs minimal in-memory
bundles directly and invokes OPA as a subprocess. That makes it
reproducible inside CI environments without external services.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Mapping, Sequence

from codegraph.evaluation.lexical_noise import (
    LexicalNoiseBenchmark,
    LexicalNoiseCase,
)
from codegraph.evaluation.uncertainty import (
    bootstrap_paired_delta_ci,
    bootstrap_prf_ci,
    paired_classifier_mcnemar,
)
from codegraph.policy.runtime.opa import evaluate_bundle
from codegraph.policy.source_analysis import analyze_policy_indicators
from codegraph.policy.source_analysis_core import strip_java_lexical_noise

from baselines.semgrep.runner import SemgrepRunResult


_PUBLIC_METHOD_RE = re.compile(
    r"public\s+(?:static\s+|final\s+|synchronized\s+|abstract\s+|native\s+)*"
    r"[\w<>\[\],\s]+?\s+(?P<name>\w+)\s*\((?P<params>[^)]*)\)",
)


METHODS = ("pre_f10", "post_f10", "semgrep")


@dataclass(frozen=True)
class DetectionResult:
    """One method's verdict on one case."""

    case_id: str
    method: str  # "pre_f10" | "post_f10" | "semgrep"
    fired_violation_ids: tuple[str, ...]
    target_fired: bool


@dataclass(frozen=True)
class CaseRow:
    case_id: str
    file_name: str
    fp_source: str
    expected: str
    target_violation_ids: tuple[str, ...]
    by_method: Mapping[str, DetectionResult]

    def label_is_positive(self) -> bool:
        return self.expected == "positive"


@dataclass(frozen=True)
class MethodMetrics:
    name: str
    tp: int
    fp: int
    tn: int
    fn: int
    precision: float
    recall: float
    f1: float
    bootstrap: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_outcomes(
        cls,
        name: str,
        outcomes: Sequence[tuple[bool, bool]],
        *,
        n_resamples: int = 2000,
        seed: int = 0,
    ) -> "MethodMetrics":
        tp = sum(1 for pred, label in outcomes if pred and label)
        fp = sum(1 for pred, label in outcomes if pred and not label)
        tn = sum(1 for pred, label in outcomes if not pred and not label)
        fn = sum(1 for pred, label in outcomes if not pred and label)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
        bootstrap = bootstrap_prf_ci(outcomes, n_resamples=n_resamples, seed=seed)
        return cls(
            name=name,
            tp=tp,
            fp=fp,
            tn=tn,
            fn=fn,
            precision=precision,
            recall=recall,
            f1=f1,
            bootstrap=bootstrap,
        )


@dataclass(frozen=True)
class StratumMetrics:
    """Metrics for one ``fp_source`` stratum (e.g. ``line_comment``)."""

    stratum: str
    n_cases: int
    n_positive: int
    n_negative: int
    methods: Mapping[str, MethodMetrics]


@dataclass(frozen=True)
class PairedComparison:
    """Paired classifier comparison: McNemar's exact + ΔFPR / ΔFNR CIs."""

    method_a: str
    method_b: str
    scope: str  # "overall" | "fp_class" | per-stratum name
    mcnemar: Mapping[str, Any]
    delta_fpr: Mapping[str, Any]
    delta_fnr: Mapping[str, Any]


@dataclass(frozen=True)
class EvalReport:
    benchmark_id: str
    n_cases: int
    rows: tuple[CaseRow, ...]
    metrics: Mapping[str, MethodMetrics]
    per_stratum: Mapping[str, StratumMetrics] = field(default_factory=dict)
    paired: tuple[PairedComparison, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "benchmark_id": self.benchmark_id,
            "n_cases": self.n_cases,
            "metrics": {
                name: {
                    **{k: v for k, v in asdict(m).items() if k != "bootstrap"},
                    "bootstrap": dict(m.bootstrap),
                }
                for name, m in self.metrics.items()
            },
            "per_stratum": {
                stratum: {
                    "stratum": s.stratum,
                    "n_cases": s.n_cases,
                    "n_positive": s.n_positive,
                    "n_negative": s.n_negative,
                    "methods": {
                        name: {
                            **{
                                k: v
                                for k, v in asdict(m).items()
                                if k != "bootstrap"
                            },
                            "bootstrap": dict(m.bootstrap),
                        }
                        for name, m in s.methods.items()
                    },
                }
                for stratum, s in self.per_stratum.items()
            },
            "paired": [
                {
                    "method_a": p.method_a,
                    "method_b": p.method_b,
                    "scope": p.scope,
                    "mcnemar": dict(p.mcnemar),
                    "delta_fpr": dict(p.delta_fpr),
                    "delta_fnr": dict(p.delta_fnr),
                }
                for p in self.paired
            ],
            "rows": [
                {
                    "case_id": row.case_id,
                    "file_name": row.file_name,
                    "fp_source": row.fp_source,
                    "expected": row.expected,
                    "target_violation_ids": list(row.target_violation_ids),
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


_DEFAULT_FQN_PACKAGE = "com.codegraph.lexicalnoise"


def _extract_target_method(
    case_id: str,
    source: str,
    *,
    package: str = _DEFAULT_FQN_PACKAGE,
) -> str:
    """Derive a deterministic ``target_method`` from the *active* source.

    The substring "HttpServletRequest" inside ``target_method`` is what
    drives the Rego ``servlet_context`` predicate on the active-code
    path (independent of ``source_code``). We extract the active method
    signature here so pre-F10 and post-F10 differ only in
    ``source_code`` — exactly the variable F10 controls.

    The regex is run on the comment-stripped active view so a
    ``// public Foo bar(...)`` line cannot fake a method signature from
    comment text.

    ``package`` should match the actual JVM package of ``source`` so
    operators reading ``detection_per_case.json`` get a meaningful FQN
    rather than the synthetic LexicalNoiseJava prefix.
    """

    active = strip_java_lexical_noise(source, strip_string_literals=False)
    match = _PUBLIC_METHOD_RE.search(active)
    if not match:
        return f"{package}.{case_id}.unknown()"
    method_name = match.group("name")
    params_raw = match.group("params").strip()
    param_types: list[str] = []
    if params_raw:
        for piece in params_raw.split(","):
            tokens = piece.strip().split()
            if len(tokens) >= 2:
                param_types.append(tokens[-2])
            elif tokens:
                param_types.append(tokens[0])
    return f"{package}.{case_id}.{method_name}({','.join(param_types)})"


def _build_minimal_bundle(
    source: str,
    *,
    file_path: str,
    target_method: str,
    f10_active: bool,
) -> Dict[str, Any]:
    """Build a minimal OPA bundle mirroring the production wiring.

    Pre-F10 (``f10_active=False``) reproduces the pre-F10 pipeline:
    ``source_code`` is the raw fixture and ``analysis_flags`` is the
    output of the policy indicator analyzer over that same raw source —
    so comment / literal mentions of MD5, getParameter, etc. influence
    the flags. This is the failure mode F10 was designed to address.

    Post-F10 (``f10_active=True``) reproduces the production wiring:
    ``source_code`` is the substring-safe view (everything blanked) and
    ``analysis_flags`` is computed on the active-code view (literals
    preserved). The Rego rules combine the two.
    """

    if f10_active:
        source_active = strip_java_lexical_noise(source, strip_string_literals=False)
        source_for_rego = strip_java_lexical_noise(source, strip_string_literals=True)
        analysis_flags = analyze_policy_indicators(source_active)
    else:
        source_for_rego = source
        analysis_flags = analyze_policy_indicators(source)

    return {
        "target_method": target_method,
        "file_path": file_path,
        "source_code": source_for_rego,
        "source_code_raw": source,
        "graph_context": {
            "annotations": [],
            "uses_fields": [],
            "calls": [],
            "callers": [],
        },
        "vector_context": [],
        "analysis_flags": analysis_flags,
        "helper_summaries": {},
        "start_line": 1,
        "end_line": len(source.splitlines()) or 1,
    }


def _fired_ids(violations: Sequence[Mapping[str, Any]]) -> tuple[str, ...]:
    seen: set[str] = set()
    for v in violations:
        vid = v.get("violation_id")
        if vid:
            seen.add(str(vid))
    return tuple(sorted(seen))


def detect_via_opa(
    case: LexicalNoiseCase,
    source: str,
    *,
    file_path: str,
    f10_active: bool,
) -> DetectionResult:
    target_method = _extract_target_method(case.case_id, source)
    bundle = _build_minimal_bundle(
        source,
        file_path=file_path,
        target_method=target_method,
        f10_active=f10_active,
    )
    violations = evaluate_bundle(bundle)
    fired = _fired_ids(violations)
    target_fired = bool(set(case.target_violation_ids) & set(fired))
    return DetectionResult(
        case_id=case.case_id,
        method="post_f10" if f10_active else "pre_f10",
        fired_violation_ids=fired,
        target_fired=target_fired,
    )


def detect_via_semgrep(
    case: LexicalNoiseCase,
    semgrep_result: SemgrepRunResult,
) -> DetectionResult:
    fired_ids: set[str] = set()
    for finding in semgrep_result.findings:
        if Path(finding.file_path).name != case.file_name:
            continue
        cg_id = finding.codegraph_violation_id
        if cg_id:
            fired_ids.add(cg_id)
    fired = tuple(sorted(fired_ids))
    target_fired = bool(set(case.target_violation_ids) & fired_ids)
    return DetectionResult(
        case_id=case.case_id,
        method="semgrep",
        fired_violation_ids=fired,
        target_fired=target_fired,
    )


def evaluate_benchmark(
    benchmark: LexicalNoiseBenchmark,
    project_root: Path,
    semgrep_result: SemgrepRunResult,
    *,
    n_resamples: int = 2000,
    seed: int = 0,
) -> EvalReport:
    java_root = benchmark.resolve_java_root(project_root)
    fixture_root_relative = benchmark.fixture_root_relative

    rows: list[CaseRow] = []
    outcomes_by_method: Dict[str, list[tuple[bool, bool]]] = {m: [] for m in METHODS}

    package_path = benchmark.package.replace(".", "/")
    for case in benchmark.cases:
        java_file = java_root / package_path / case.file_name
        source = java_file.read_text(encoding="utf-8")
        rel_path = f"{fixture_root_relative}/{benchmark.java_relative_root}/{package_path}/{case.file_name}"

        pre = detect_via_opa(case, source, file_path=rel_path, f10_active=False)
        post = detect_via_opa(case, source, file_path=rel_path, f10_active=True)
        smg = detect_via_semgrep(case, semgrep_result)

        by_method = {"pre_f10": pre, "post_f10": post, "semgrep": smg}
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
        for method in METHODS:
            outcomes_by_method[method].append((by_method[method].target_fired, label))

    metrics = {
        method: MethodMetrics.from_outcomes(
            method, outcomes_by_method[method], n_resamples=n_resamples, seed=seed
        )
        for method in METHODS
    }

    per_stratum = _compute_per_stratum(rows, n_resamples=n_resamples, seed=seed)
    paired = _compute_paired_comparisons(
        rows, n_resamples=n_resamples, seed=seed, per_stratum=per_stratum
    )

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
) -> Dict[str, StratumMetrics]:
    """Group rows by ``fp_source`` and compute per-stratum metrics.

    Per-stratum bootstrap CIs are intentionally retained (rather than
    suppressed): they will be wide at n≈5-6 per stratum, which honestly
    communicates that single-stratum point estimates are imprecise. The
    diagnostic value is the *pattern* — F10 should eliminate FPs in
    comment strata while leaving literal / text-block strata untouched.
    """

    grouped: Dict[str, list[CaseRow]] = {}
    for row in rows:
        grouped.setdefault(row.fp_source, []).append(row)

    out: Dict[str, StratumMetrics] = {}
    for stratum in sorted(grouped.keys()):
        s_rows = grouped[stratum]
        s_methods: Dict[str, MethodMetrics] = {}
        for method in METHODS:
            outcomes = [
                (r.by_method[method].target_fired, r.expected == "positive")
                for r in s_rows
            ]
            s_methods[method] = MethodMetrics.from_outcomes(
                method, outcomes, n_resamples=n_resamples, seed=seed
            )
        out[stratum] = StratumMetrics(
            stratum=stratum,
            n_cases=len(s_rows),
            n_positive=sum(1 for r in s_rows if r.expected == "positive"),
            n_negative=sum(1 for r in s_rows if r.expected == "negative"),
            methods=s_methods,
        )
    return out


def _paired_triples(
    rows: Sequence[CaseRow], method_a: str, method_b: str
) -> list[tuple[bool, bool, bool]]:
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
    """Paired tests for the headline F10 contract: post_f10 vs pre_f10.

    Three scopes:
      * ``overall`` — every case, two-sided McNemar's, ΔFPR / ΔFNR.
      * ``fp_class`` — only NEG cases, FP-class restricted McNemar
        (asks "did F10 reduce FPs significantly?"), ΔFPR / ΔFNR.
      * ``stratum:<fp_source>`` — one per lexical stratum, scoped to that
        stratum's cases. Diagnostic decomposition; n≈5-6 per stratum, so
        per-stratum p-values may not reach α=0.05 even when the effect is
        real — read these as descriptive, not as confirmatory tests.
    """

    method_a, method_b = "pre_f10", "post_f10"
    out: list[PairedComparison] = []

    all_paired = _paired_triples(rows, method_a, method_b)
    out.append(
        PairedComparison(
            method_a=method_a,
            method_b=method_b,
            scope="overall",
            mcnemar=paired_classifier_mcnemar(all_paired),
            delta_fpr=bootstrap_paired_delta_ci(
                all_paired, metric="fpr", n_resamples=n_resamples, seed=seed
            ),
            delta_fnr=bootstrap_paired_delta_ci(
                all_paired, metric="fnr", n_resamples=n_resamples, seed=seed
            ),
        )
    )
    out.append(
        PairedComparison(
            method_a=method_a,
            method_b=method_b,
            scope="fp_class",
            mcnemar=paired_classifier_mcnemar(all_paired, restrict_to="fp_class"),
            delta_fpr=bootstrap_paired_delta_ci(
                all_paired, metric="fpr", n_resamples=n_resamples, seed=seed
            ),
            delta_fnr=bootstrap_paired_delta_ci(
                all_paired, metric="fnr", n_resamples=n_resamples, seed=seed
            ),
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
                delta_fpr=bootstrap_paired_delta_ci(
                    s_paired,
                    metric="fpr",
                    n_resamples=n_resamples,
                    seed=seed,
                ),
                delta_fnr=bootstrap_paired_delta_ci(
                    s_paired,
                    metric="fnr",
                    n_resamples=n_resamples,
                    seed=seed,
                ),
            )
        )
    return tuple(out)


def format_markdown_summary(report: EvalReport) -> str:
    """Render a Markdown summary table suitable for the thesis chapter."""

    header = (
        f"# LexicalNoiseJava — Detection Summary ({report.benchmark_id}, n={report.n_cases})\n\n"
        "| Method | TP | FP | TN | FN | Precision | Recall | F1 | P CI (95%) | R CI (95%) | F1 CI (95%) |\n"
        "|---|---:|---:|---:|---:|---:|---:|---:|---|---|---|\n"
    )
    rows = []
    for method in METHODS:
        m = report.metrics[method]
        b = m.bootstrap
        p_ci = b.get("precision", {})
        r_ci = b.get("recall", {})
        f_ci = b.get("f1", {})
        rows.append(
            "| {name} | {tp} | {fp} | {tn} | {fn} | {p:.3f} | {r:.3f} | {f:.3f} "
            "| [{p_lo:.3f}, {p_hi:.3f}] | [{r_lo:.3f}, {r_hi:.3f}] | [{f_lo:.3f}, {f_hi:.3f}] |".format(
                name=m.name,
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
        )
    table = header + "\n".join(rows) + "\n"

    return (
        table
        + _format_paired_section(report)
        + _format_per_stratum_section(report)
        + _format_per_case_section(report)
    )


def _format_paired_section(report: EvalReport) -> str:
    if not report.paired:
        return ""
    lines = [
        "\n## Effect of F10 (post_f10 vs pre_f10)\n",
        "Per-case paired analysis. McNemar's exact binomial test "
        "is reported for ΔFP and Δ(any) — for n_disagreements = 0 "
        "the test is undefined and the cell reads `n/a (b=c=0)`. "
        "Δ rates are bootstrapped on the *paired* sample.\n",
        "| Scope | b (improvements) | c (regressions) | McNemar p (exact) "
        "| ΔFPR (post − pre) | ΔFPR 95% CI | ΔFNR (post − pre) | ΔFNR 95% CI |",
        "|---|---:|---:|---|---:|---|---:|---|",
    ]
    for pc in report.paired:
        mc = pc.mcnemar
        fpr = pc.delta_fpr
        fnr = pc.delta_fnr
        if mc.get("test_defined"):
            p_cell = f"{mc['p_value']:.4f}"
        else:
            p_cell = "n/a (b=c=0)"
        lines.append(
            "| {scope} | {b} | {c} | {p} | {dfpr:+.3f} | [{flo:+.3f}, {fhi:+.3f}] "
            "| {dfnr:+.3f} | [{nlo:+.3f}, {nhi:+.3f}] |".format(
                scope=pc.scope,
                b=mc.get("b", 0),
                c=mc.get("c", 0),
                p=p_cell,
                dfpr=fpr.get("point", 0.0),
                flo=fpr.get("ci_low", 0.0),
                fhi=fpr.get("ci_high", 0.0),
                dfnr=fnr.get("point", 0.0),
                nlo=fnr.get("ci_low", 0.0),
                nhi=fnr.get("ci_high", 0.0),
            )
        )
    return "\n".join(lines) + "\n"


def _format_per_stratum_section(report: EvalReport) -> str:
    if not report.per_stratum:
        return ""
    lines = [
        "\n## Per-stratum decomposition (by fp_source)\n",
        "Diagnostic breakdown of F10's effect by lexical-noise source type. "
        "Single-stratum CIs are wide at n≈5-6 — read the *pattern* (comment "
        "strata cleaned, literal / text-block strata unchanged), not the "
        "point estimates.\n",
        "| Stratum | n | n_pos | n_neg | Method | TP | FP | TN | FN "
        "| Precision | Recall | F1 |",
        "|---|---:|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for stratum in sorted(report.per_stratum.keys()):
        s = report.per_stratum[stratum]
        for method in METHODS:
            m = s.methods[method]
            lines.append(
                "| {st} | {n} | {npos} | {nneg} | {meth} | {tp} | {fp} | {tn} | {fn} "
                "| {p:.3f} | {r:.3f} | {f:.3f} |".format(
                    st=s.stratum,
                    n=s.n_cases,
                    npos=s.n_positive,
                    nneg=s.n_negative,
                    meth=method,
                    tp=m.tp,
                    fp=m.fp,
                    tn=m.tn,
                    fn=m.fn,
                    p=m.precision,
                    r=m.recall,
                    f=m.f1,
                )
            )
    return "\n".join(lines) + "\n"


def _format_per_case_section(report: EvalReport) -> str:
    out = [
        "\n## Per-case verdicts\n",
        "| Case | fp_source | expected | target | pre_f10 | post_f10 | semgrep |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in report.rows:
        out.append(
            "| {cid} | {src} | {exp} | {target} | {pre} | {post} | {sem} |".format(
                cid=row.case_id,
                src=row.fp_source,
                exp=row.expected,
                target=", ".join(row.target_violation_ids),
                pre="fire" if row.by_method["pre_f10"].target_fired else "—",
                post="fire" if row.by_method["post_f10"].target_fired else "—",
                sem="fire" if row.by_method["semgrep"].target_fired else "—",
            )
        )
    return "\n".join(out) + "\n"
