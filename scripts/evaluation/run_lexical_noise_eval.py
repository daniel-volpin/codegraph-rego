"""Run the LexicalNoiseJava detection eval (Phase D of F10).

Produces a three-column comparison — pre_f10 / post_f10 / semgrep —
on the 30-case LexicalNoiseJava benchmark. Outputs:

* ``detection_per_case.json`` — typed per-case verdicts and aggregate
  metrics with bootstrap CIs (input to thesis-tables generators).
* ``summary.md`` — Markdown summary + per-case verdict table.
* ``semgrep_baseline.json`` — raw SemGrep findings (Phase C artefact).
* ``provenance.json`` — Git SHA, OPA version, config sha256, etc.

The script is LLM-free and Neo4j-free; it invokes OPA and SemGrep as
subprocesses and constructs minimal in-memory bundles.

Example::

    .venv/bin/python run_lexical_noise_eval.py \\
        --output-dir outputs/lexical_noise_eval_v1 \\
        --seed 42
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from baselines.semgrep.runner import run_semgrep_baseline

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from codegraph.evaluation.lexical_noise import load_lexical_noise_manifest  # noqa: E402
from codegraph.evaluation.lexical_noise_eval import (  # noqa: E402
    evaluate_benchmark,
    format_markdown_summary,
)
from codegraph.evaluation.provenance import collect_provenance, write_provenance  # noqa: E402

_DEFAULT_MANIFEST = "configs/benchmark/lexical_noise_v1.json"


def _build_argparser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=".venv/bin/python run_lexical_noise_eval.py",
        description="LexicalNoiseJava detection eval: pre_f10 vs post_f10 vs SemGrep.",
    )
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path(_DEFAULT_MANIFEST),
        help=f"Path to benchmark manifest (default: {_DEFAULT_MANIFEST}).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Directory to write detection_per_case.json, summary.md, provenance.json.",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=0,
        help="Bootstrap RNG seed (default: 0).",
    )
    parser.add_argument(
        "--n-resamples",
        type=int,
        default=2000,
        help="Bootstrap resample count for PRF CIs (default: 2000).",
    )
    parser.add_argument(
        "--semgrep-registry-config",
        type=str,
        default=None,
        help=(
            "Optional SemGrep registry pack (e.g. 'p/java', 'p/owasp-top-ten') "
            "to run as a 4th comparison column. Requires network access; "
            "skipped silently if SemGrep cannot fetch the pack."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_argparser()
    args = parser.parse_args(argv)

    project_root = Path(__file__).resolve().parent

    if not args.manifest.exists():
        print(f"error: manifest not found: {args.manifest}", file=sys.stderr)
        return 2

    benchmark = load_lexical_noise_manifest(args.manifest)
    fixture_root = benchmark.resolve_fixture_root(project_root)

    semgrep_result = run_semgrep_baseline(target=fixture_root)

    semgrep_registry_result = None
    if args.semgrep_registry_config:
        try:
            semgrep_registry_result = run_semgrep_baseline(
                target=fixture_root,
                rules_dir=None,
                registry_config=args.semgrep_registry_config,
            )
            print(
                f"semgrep registry ({args.semgrep_registry_config}): "
                f"{len(semgrep_registry_result.findings)} findings"
            )
        except RuntimeError as exc:
            print(
                f"warning: SemGrep registry config {args.semgrep_registry_config!r} "
                f"failed; continuing without it ({exc})",
                file=sys.stderr,
            )
            semgrep_registry_result = None

    report = evaluate_benchmark(
        benchmark,
        project_root,
        semgrep_result,
        n_resamples=args.n_resamples,
        seed=args.seed,
        semgrep_registry_result=semgrep_registry_result,
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
        eval_kind="lexical_noise_v1",
        config_path=args.manifest,
        output_dir=output_dir,
        seed=args.seed,
        extra={
            "n_resamples": args.n_resamples,
            "n_cases": report.n_cases,
            "semgrep_findings": len(semgrep_result.findings),
            "metrics_summary": {
                method: {
                    "tp": m.tp,
                    "fp": m.fp,
                    "tn": m.tn,
                    "fn": m.fn,
                    "precision": m.precision,
                    "recall": m.recall,
                    "f1": m.f1,
                }
                for method, m in report.metrics.items()
            },
        },
    )
    write_provenance(provenance, output_dir)

    print(f"wrote {output_dir}/summary.md  n_cases={report.n_cases}")
    for method, m in report.metrics.items():
        print(
            f"  {method:>9}: TP={m.tp:3d}  FP={m.fp:3d}  TN={m.tn:3d}  FN={m.fn:3d}  "
            f"P={m.precision:.3f}  R={m.recall:.3f}  F1={m.f1:.3f}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
