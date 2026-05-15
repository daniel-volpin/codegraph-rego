"""Run the OWASP Benchmark file-level F10 eval (Phase D, OWASP extension).

Quantifies F10's marginal contribution on the OWASP Benchmark v1.2
Java testcase corpus. Uses the same dual-mode (pre_f10 vs post_f10)
detection harness as ``run_lexical_noise_eval.py`` plus the Phase C
SemGrep baseline.

OWASP root resolution order:
    1. ``--owasp-root <dir>`` argument
    2. ``$OWASP_BENCHMARK_ROOT`` env var
    3. ``.benchmark_cache/owasp-benchmark/``
    4. ``/tmp/owasp-benchmark/``

Outputs (gitignored under ``outputs/``):
    - ``detection_per_case.json``
    - ``summary.md`` (overall + per-CWE tables with bootstrap CIs)
    - ``semgrep_baseline.json``
    - ``provenance.json``

LLM-free, Neo4j-free; the file-level eval measures F10's marginal
contribution independent of graph context.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from baselines.semgrep.runner import run_semgrep_baseline
from codegraph.evaluation.owasp_lexical_eval import (
    SUPPORTED_CWES,
    evaluate_owasp,
    format_markdown_summary,
    load_owasp_cases,
)
from codegraph.evaluation.provenance import collect_provenance, write_provenance


_PROJECT_ROOT = Path(__file__).resolve().parent
_DEFAULT_CACHE = _PROJECT_ROOT / ".benchmark_cache" / "owasp-benchmark"
_FALLBACK_TMP = Path("/tmp/owasp-benchmark")


def _resolve_owasp_root(explicit: Path | None) -> Path | None:
    candidates: list[Path] = []
    if explicit is not None:
        candidates.append(explicit)
    env = os.environ.get("OWASP_BENCHMARK_ROOT")
    if env:
        candidates.append(Path(env))
    candidates.append(_DEFAULT_CACHE)
    candidates.append(_FALLBACK_TMP)
    for c in candidates:
        if c.is_dir() and (c / "expectedresults-1.2.csv").is_file():
            return c
    return None


def _build_argparser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=".venv/bin/python run_owasp_lexical_eval.py",
        description="OWASP Benchmark file-level F10 eval (pre_f10 vs post_f10 vs SemGrep).",
    )
    parser.add_argument(
        "--owasp-root",
        type=Path,
        default=None,
        help="OWASP Benchmark v1.2 repo root (containing expectedresults-1.2.csv).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Directory to write detection_per_case.json, summary.md, provenance.json.",
    )
    parser.add_argument(
        "--limit-per-cwe",
        type=int,
        default=50,
        help="Cap cases per CWE (default 50). Pass 0 for no cap (~2,092 cases, ~10 min serial).",
    )
    parser.add_argument(
        "--cwes",
        nargs="*",
        default=None,
        help="Restrict to specific CWE numbers (default: all 8 supported CWEs).",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=0,
        help="Sampling + bootstrap RNG seed (default 0).",
    )
    parser.add_argument(
        "--n-resamples",
        type=int,
        default=2000,
        help="Bootstrap resample count for PRF CIs (default 2000).",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=None,
        help="OPA worker processes (default: cpu_count - 1).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_argparser()
    args = parser.parse_args(argv)

    owasp_root = _resolve_owasp_root(args.owasp_root)
    if owasp_root is None:
        print(
            "error: OWASP Benchmark not found.\n"
            "  Tried: --owasp-root, $OWASP_BENCHMARK_ROOT, "
            f"{_DEFAULT_CACHE}, {_FALLBACK_TMP}.\n"
            "  Clone with:\n"
            "    git clone --depth=1 https://github.com/OWASP-Benchmark/BenchmarkJava.git \\\n"
            f"      {_DEFAULT_CACHE}",
            file=sys.stderr,
        )
        return 2

    csv_path = owasp_root / "expectedresults-1.2.csv"
    java_root = owasp_root / "src" / "main" / "java" / "org" / "owasp" / "benchmark" / "testcode"
    if not java_root.is_dir():
        print(f"error: OWASP Java testcode dir not found: {java_root}", file=sys.stderr)
        return 2

    cwes_arg = None
    if args.cwes:
        unknown = set(args.cwes) - SUPPORTED_CWES
        if unknown:
            print(
                f"error: unsupported CWEs: {sorted(unknown)}. "
                f"Supported: {sorted(SUPPORTED_CWES)}",
                file=sys.stderr,
            )
            return 2
        cwes_arg = args.cwes

    limit = None if args.limit_per_cwe == 0 else args.limit_per_cwe
    cases = load_owasp_cases(
        csv_path,
        java_root,
        cwes=cwes_arg,
        limit_per_cwe=limit,
        seed=args.seed,
    )
    if not cases:
        print("error: no OWASP cases matched the requested filter.", file=sys.stderr)
        return 2

    print(f"loaded {len(cases)} OWASP cases from {owasp_root}")

    semgrep_result = run_semgrep_baseline(target=java_root)
    print(f"semgrep: {len(semgrep_result.findings)} findings across {len(cases)} files")

    report = evaluate_owasp(
        cases,
        java_root=java_root,
        semgrep_result=semgrep_result,
        n_resamples=args.n_resamples,
        seed=args.seed,
        workers=args.workers,
    )

    output_dir = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    (output_dir / "detection_per_case.json").write_text(
        json.dumps(report.to_dict(), indent=2, sort_keys=True), encoding="utf-8"
    )
    (output_dir / "summary.md").write_text(
        format_markdown_summary(report), encoding="utf-8"
    )
    (output_dir / "semgrep_baseline.json").write_text(
        json.dumps(
            {
                "target": str(semgrep_result.target),
                "rules_path": str(semgrep_result.rules_path),
                "findings": [
                    {
                        "rule_id": f.rule_id,
                        "codegraph_violation_id": f.codegraph_violation_id,
                        "file_path": f.file_path,
                        "start_line": f.start_line,
                        "end_line": f.end_line,
                    }
                    for f in semgrep_result.findings
                ],
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    provenance = collect_provenance(
        eval_kind="owasp_benchmark_v1.2_file_level",
        config_path=csv_path,
        output_dir=output_dir,
        seed=args.seed,
        extra={
            "n_cases": report.n_cases,
            "limit_per_cwe": limit,
            "cwes_evaluated": list(report.cwes_evaluated),
            "n_resamples": args.n_resamples,
            "semgrep_findings": len(semgrep_result.findings),
            "owasp_benchmark_root": str(owasp_root),
            "metrics_overall": {
                method: {
                    "tp": m.tp,
                    "fp": m.fp,
                    "tn": m.tn,
                    "fn": m.fn,
                    "precision": m.precision,
                    "recall": m.recall,
                    "f1": m.f1,
                }
                for method, m in report.overall.items()
            },
        },
    )
    write_provenance(provenance, output_dir)

    print(f"wrote {output_dir}/summary.md  n_cases={report.n_cases}")
    for method, m in report.overall.items():
        print(
            f"  {method:>9}: TP={m.tp:4d}  FP={m.fp:4d}  TN={m.tn:4d}  FN={m.fn:4d}  "
            f"P={m.precision:.3f}  R={m.recall:.3f}  F1={m.f1:.3f}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
