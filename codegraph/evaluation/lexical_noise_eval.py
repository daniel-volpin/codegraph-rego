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
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from baselines.semgrep.runner import SemgrepRunResult
from codegraph.evaluation.lexical_noise import (
    LexicalNoiseBenchmark,
    LexicalNoiseCase,
)
from codegraph.evaluation.lexical_noise_engine import evaluate_benchmark_cases
from codegraph.evaluation.lexical_noise_formatter import format_markdown_summary
from codegraph.evaluation.lexical_noise_report_models import (
    METHODS,
    SEMGREP_REGISTRY_METHOD,
    CaseRow,
    DetectionResult,
    EvalReport,
    MethodMetrics,
    PairedComparison,
    StratumMetrics,
    report_methods,
)
from codegraph.policy.runtime.opa import evaluate_bundle
from codegraph.policy.source_analysis import analyze_policy_indicators
from codegraph.policy.source_analysis_core import strip_java_lexical_noise

__all__ = [
    "METHODS",
    "SEMGREP_REGISTRY_METHOD",
    "CaseRow",
    "DetectionResult",
    "EvalReport",
    "MethodMetrics",
    "PairedComparison",
    "StratumMetrics",
    "detect_via_opa",
    "detect_via_semgrep",
    "detect_via_semgrep_registry",
    "evaluate_benchmark",
    "format_markdown_summary",
    "report_methods",
]

_PUBLIC_METHOD_RE = re.compile(
    r"public\s+(?:static\s+|final\s+|synchronized\s+|abstract\s+|native\s+)*"
    r"[\w<>\[\],\s]+?\s+(?P<name>\w+)\s*\((?P<params>[^)]*)\)",
)

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
) -> dict[str, Any]:
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


def detect_via_semgrep_registry(
    case: LexicalNoiseCase,
    semgrep_result: SemgrepRunResult,
) -> DetectionResult:
    """Per-case verdict for a SemGrep registry baseline.

    Registry rule ids (e.g.
    ``java.lang.security.audit.crypto.unsafe-md5.unsafe-md5``) do not
    map deterministically to CodeGraph violation IDs, so the verdict
    is *any* finding on the case's file. For LexicalNoiseJava this is
    the right binary semantic: a NEG case should produce zero findings
    (the registry resists lexical noise via its AST matcher) and a POS
    case should produce at least one (the registry should catch real
    sinks).
    """

    matched = [f for f in semgrep_result.findings if Path(f.file_path).name == case.file_name]
    fired = tuple(sorted({f.rule_id for f in matched}))
    return DetectionResult(
        case_id=case.case_id,
        method=SEMGREP_REGISTRY_METHOD,
        fired_violation_ids=fired,
        target_fired=bool(matched),
    )


def evaluate_benchmark(
    benchmark: LexicalNoiseBenchmark,
    project_root: Path,
    semgrep_result: SemgrepRunResult,
    *,
    n_resamples: int = 2000,
    seed: int = 0,
    semgrep_registry_result: SemgrepRunResult | None = None,
) -> EvalReport:
    return evaluate_benchmark_cases(
        benchmark,
        project_root,
        semgrep_result,
        detect_via_opa_fn=detect_via_opa,
        detect_via_semgrep_fn=detect_via_semgrep,
        detect_via_semgrep_registry_fn=detect_via_semgrep_registry,
        n_resamples=n_resamples,
        seed=seed,
        semgrep_registry_result=semgrep_registry_result,
    )
