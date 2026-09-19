from __future__ import annotations

from codegraph.evaluation.lexical_noise_report_models import METHODS, MethodMetrics
from codegraph.evaluation.owasp_lexical_models import CWE_TO_ISO, OwaspEvalReport


def _metrics_cells(m: MethodMetrics) -> str:
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
    overall_rows = "\n".join(f"| {name} |{_metrics_cells(report.overall[name])}|" for name in METHODS)

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

    paired_section = _format_owasp_paired_section(report)

    return header + overall_rows + per_cwe_header + "\n".join(per_cwe_rows) + "\n" + paired_section


def _format_owasp_paired_section(report: OwaspEvalReport) -> str:
    if not report.paired:
        return ""
    lines = [
        "\n\n## Effect of F10 (post_f10 vs pre_f10)\n",
        "Per-case paired analysis. `n/a (b=c=0)` is the expected cell "
        "value for the OWASP synthetic corpus — F10 produces zero deltas "
        "because OWASP lacks the lexical-noise FP class F10 targets.\n",
        "| Scope | b (improvements) | c (regressions) | McNemar p (exact) "
        "| ΔFPR (post − pre) | ΔFPR 95% CI | ΔFNR (post − pre) | ΔFNR 95% CI |",
        "|---|---:|---:|---|---:|---|---:|---|",
    ]
    for pc in report.paired:
        mc = pc.mcnemar
        fpr = pc.delta_fpr
        fnr = pc.delta_fnr
        p_cell = f"{mc['p_value']:.4f}" if mc.get("test_defined") else "n/a (b=c=0)"
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
