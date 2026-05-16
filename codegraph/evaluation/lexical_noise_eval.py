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
from codegraph.evaluation.uncertainty import bootstrap_prf_ci
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
class EvalReport:
    benchmark_id: str
    n_cases: int
    rows: tuple[CaseRow, ...]
    metrics: Mapping[str, MethodMetrics]

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
    return EvalReport(
        benchmark_id=benchmark.benchmark_id,
        n_cases=len(rows),
        rows=tuple(rows),
        metrics=metrics,
    )


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

    per_case = (
        "\n## Per-case verdicts\n\n"
        "| Case | fp_source | expected | target | pre_f10 | post_f10 | semgrep |\n"
        "|---|---|---|---|---|---|---|\n"
    )
    for row in report.rows:
        per_case += (
            "| {cid} | {src} | {exp} | {target} | {pre} | {post} | {sem} |\n".format(
                cid=row.case_id,
                src=row.fp_source,
                exp=row.expected,
                target=", ".join(row.target_violation_ids),
                pre="fire" if row.by_method["pre_f10"].target_fired else "—",
                post="fire" if row.by_method["post_f10"].target_fired else "—",
                sem="fire" if row.by_method["semgrep"].target_fired else "—",
            )
        )
    return table + per_case
