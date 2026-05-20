"""Multi-seed OWASP F10 stability eval.

Runs the file-level OWASP evaluator N times with different sampling
seeds and reports across-seed variance on the headline metrics. The
within-run bootstrap CIs in ``run_owasp_lexical_eval.py`` quantify
sampling noise *within* one resample partition; the multi-seed
across-run statistics here capture noise *across* the stratified
sampling itself.

This is the standard convention for cross-validation-style robustness
in SAST evaluation: a single seed is one point estimate; running with
several seeds and reporting the mean ± stddev (or min/max) shows how
sensitive the metric is to which 50 cases per CWE happened to be
drawn.

LLM-free, Neo4j-free; reuses the same OPA + SemGrep machinery as the
single-seed CLI.

Example::

    .venv/bin/python run_owasp_multiseed_eval.py \\
        --owasp-root .benchmark_cache/owasp-benchmark \\
        --output-dir outputs/owasp_multiseed_v1 \\
        --limit-per-cwe 50 \\
        --seeds 7,13,23,42,101
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path
from typing import Any, Dict, List

from baselines.semgrep.runner import run_semgrep_baseline
from codegraph.evaluation.owasp_lexical_eval import (
    SUPPORTED_CWES,
    evaluate_owasp,
    load_owasp_cases,
    owasp_corpus_sha,
    owasp_paths,
    resolve_owasp_root,
)
from codegraph.evaluation.provenance import collect_provenance, write_provenance


_METRIC_KEYS = ("tp", "fp", "tn", "fn", "precision", "recall", "f1")


def _build_argparser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=".venv/bin/python run_owasp_multiseed_eval.py",
        description="OWASP file-level F10 eval across multiple sampling seeds.",
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
        help="Directory to write multi_seed_summary.{json,md} and provenance.json.",
    )
    parser.add_argument(
        "--seeds",
        type=str,
        default="7,13,23,42,101",
        help="Comma-separated sampling seeds (default: 7,13,23,42,101).",
    )
    parser.add_argument(
        "--limit-per-cwe",
        type=int,
        default=50,
        help="Cap cases per CWE per seed (default: 50). 0 disables the cap.",
    )
    parser.add_argument(
        "--n-resamples",
        type=int,
        default=500,
        help="Within-run bootstrap resample count (default: 500). Lower than "
        "the single-seed default to keep multi-seed runtime tight.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=None,
        help="OPA worker processes per seed (default: cpu_count - 1).",
    )
    return parser


def _per_seed_summary(report: Any) -> Dict[str, Dict[str, float]]:
    return {
        method: {k: getattr(m, k) for k in _METRIC_KEYS}
        for method, m in report.overall.items()
    }


def _aggregate_across_seeds(
    per_seed: List[Dict[str, Dict[str, float]]],
) -> Dict[str, Dict[str, Dict[str, float]]]:
    """Mean / stddev / min / max across seeds for every method × metric."""

    if not per_seed:
        return {}
    methods = list(per_seed[0].keys())
    out: Dict[str, Dict[str, Dict[str, float]]] = {}
    for method in methods:
        method_summary: Dict[str, Dict[str, float]] = {}
        for metric in _METRIC_KEYS:
            values = [seed_summary[method][metric] for seed_summary in per_seed]
            method_summary[metric] = {
                "mean": statistics.fmean(values),
                "stdev": statistics.stdev(values) if len(values) > 1 else 0.0,
                "min": min(values),
                "max": max(values),
            }
        out[method] = method_summary
    return out


def _format_multi_seed_markdown(
    seeds: List[int],
    per_seed: List[Dict[str, Dict[str, float]]],
    aggregate: Dict[str, Dict[str, Dict[str, float]]],
    *,
    limit_per_cwe: int | None,
) -> str:
    head = (
        "# OWASP Benchmark v1.2 — Multi-Seed F10 Stability\n\n"
        f"Seeds: `{','.join(str(s) for s in seeds)}` "
        f"(limit_per_cwe={limit_per_cwe or 'full corpus'}).\n\n"
        "## Across-seed mean ± stdev on Precision / Recall / F1\n\n"
        "| Method | Precision (mean ± stdev) | Recall (mean ± stdev) | F1 (mean ± stdev) |\n"
        "|---|---|---|---|\n"
    )
    rows = []
    for method, summary in aggregate.items():
        p = summary["precision"]
        r = summary["recall"]
        f = summary["f1"]
        rows.append(
            "| {meth} | {pm:.3f} ± {ps:.3f} [{pmin:.3f}, {pmax:.3f}] "
            "| {rm:.3f} ± {rs:.3f} [{rmin:.3f}, {rmax:.3f}] "
            "| {fm:.3f} ± {fs:.3f} [{fmin:.3f}, {fmax:.3f}] |".format(
                meth=method,
                pm=p["mean"], ps=p["stdev"], pmin=p["min"], pmax=p["max"],
                rm=r["mean"], rs=r["stdev"], rmin=r["min"], rmax=r["max"],
                fm=f["mean"], fs=f["stdev"], fmin=f["min"], fmax=f["max"],
            )
        )

    per_seed_section = [
        "\n\n## Per-seed metrics\n\n",
        "| Seed | Method | TP | FP | TN | FN | Precision | Recall | F1 |\n",
        "|---:|---|---:|---:|---:|---:|---:|---:|---:|\n",
    ]
    for seed, seed_summary in zip(seeds, per_seed):
        for method, m in seed_summary.items():
            per_seed_section.append(
                "| {s} | {meth} | {tp:.0f} | {fp:.0f} | {tn:.0f} | {fn:.0f} "
                "| {p:.3f} | {r:.3f} | {f:.3f} |\n".format(
                    s=seed, meth=method,
                    tp=m["tp"], fp=m["fp"], tn=m["tn"], fn=m["fn"],
                    p=m["precision"], r=m["recall"], f=m["f1"],
                )
            )
    return head + "\n".join(rows) + "\n" + "".join(per_seed_section)


def main(argv: list[str] | None = None) -> int:
    parser = _build_argparser()
    args = parser.parse_args(argv)

    owasp_root = resolve_owasp_root(args.owasp_root)
    if owasp_root is None:
        print(
            "error: OWASP Benchmark not found (see --help for resolution order).",
            file=sys.stderr,
        )
        return 2

    csv_path, java_root = owasp_paths(owasp_root)
    if not java_root.is_dir():
        print(f"error: OWASP Java testcode dir not found: {java_root}", file=sys.stderr)
        return 2

    try:
        seeds = [int(s.strip()) for s in args.seeds.split(",") if s.strip()]
    except ValueError:
        print(f"error: --seeds must be comma-separated ints, got {args.seeds!r}", file=sys.stderr)
        return 2
    if not seeds:
        print("error: --seeds must contain at least one seed", file=sys.stderr)
        return 2

    limit = None if args.limit_per_cwe == 0 else args.limit_per_cwe

    # SemGrep is deterministic for a fixed corpus, so we run it once and
    # reuse the result across seeds; only the OWASP case sampling changes.
    semgrep_result = run_semgrep_baseline(target=java_root)

    per_seed_overall: List[Dict[str, Dict[str, float]]] = []
    for seed in seeds:
        print(f"seed={seed}: loading & evaluating...")
        cases = load_owasp_cases(
            csv_path,
            java_root,
            cwes=list(SUPPORTED_CWES),
            limit_per_cwe=limit,
            seed=seed,
        )
        report = evaluate_owasp(
            cases,
            java_root=java_root,
            semgrep_result=semgrep_result,
            n_resamples=args.n_resamples,
            seed=seed,
            workers=args.workers,
        )
        per_seed_overall.append(_per_seed_summary(report))

    aggregate = _aggregate_across_seeds(per_seed_overall)

    output_dir = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    (output_dir / "multi_seed_summary.json").write_text(
        json.dumps(
            {
                "seeds": seeds,
                "limit_per_cwe": limit,
                "per_seed_overall": per_seed_overall,
                "across_seed": aggregate,
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (output_dir / "multi_seed_summary.md").write_text(
        _format_multi_seed_markdown(
            seeds, per_seed_overall, aggregate, limit_per_cwe=limit
        ),
        encoding="utf-8",
    )

    provenance = collect_provenance(
        eval_kind="owasp_benchmark_v1.2_multiseed",
        config_path=csv_path,
        output_dir=output_dir,
        seed=seeds[0],  # primary seed; full list in extra
        extra={
            "seeds": seeds,
            "limit_per_cwe": limit,
            "n_resamples": args.n_resamples,
            "owasp_benchmark_root": str(owasp_root),
            "owasp_benchmark_sha": owasp_corpus_sha(owasp_root),
            "semgrep_findings": len(semgrep_result.findings),
            "across_seed": aggregate,
        },
    )
    write_provenance(provenance, output_dir)

    print(f"\nwrote {output_dir}/multi_seed_summary.md  seeds={seeds}")
    for method, summary in aggregate.items():
        f = summary["f1"]
        p = summary["precision"]
        r = summary["recall"]
        print(
            f"  {method:>9}: "
            f"P = {p['mean']:.3f} ± {p['stdev']:.3f}  "
            f"R = {r['mean']:.3f} ± {r['stdev']:.3f}  "
            f"F1 = {f['mean']:.3f} ± {f['stdev']:.3f}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
