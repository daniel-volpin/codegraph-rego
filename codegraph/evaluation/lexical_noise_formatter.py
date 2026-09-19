from __future__ import annotations

from codegraph.evaluation.lexical_noise_report_models import EvalReport, report_methods


def format_markdown_summary(report: EvalReport) -> str:
    """Render a Markdown summary table suitable for the thesis chapter."""
    header = (
        f"# LexicalNoiseJava — Detection Summary ({report.benchmark_id}, n={report.n_cases})\n\n"
        "| Method | TP | FP | TN | FN | Precision | Recall | F1 | P CI (95%) | R CI (95%) | F1 CI (95%) |\n"
        "|---|---:|---:|---:|---:|---:|---:|---:|---|---|---|\n"
    )
    rows = []
    for method in report_methods(report):
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
        table + _format_paired_section(report) + _format_per_stratum_section(report) + _format_per_case_section(report)
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
        "| Stratum | n | n_pos | n_neg | Method | TP | FP | TN | FN | Precision | Recall | F1 |",
        "|---|---:|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    methods = report_methods(report)
    for stratum in sorted(report.per_stratum.keys()):
        s = report.per_stratum[stratum]
        for method in methods:
            if method not in s.methods:
                continue
            m = s.methods[method]
            lines.append(
                f"| {s.stratum} | {s.n_cases} | {s.n_positive} | {s.n_negative} | {method} | {m.tp} | {m.fp} | {m.tn} | {m.fn} "
                f"| {m.precision:.3f} | {m.recall:.3f} | {m.f1:.3f} |"
            )
    return "\n".join(lines) + "\n"


def _format_per_case_section(report: EvalReport) -> str:
    methods = report_methods(report)
    header_cells = ["Case", "fp_source", "expected", "target"] + list(methods)
    out = [
        "\n## Per-case verdicts\n",
        "| " + " | ".join(header_cells) + " |",
        "|" + "|".join("---" for _ in header_cells) + "|",
    ]
    for row in report.rows:
        cells = [
            row.case_id,
            row.fp_source,
            row.expected,
            ", ".join(row.target_violation_ids),
        ]
        for method in methods:
            if method in row.by_method:
                cells.append("fire" if row.by_method[method].target_fired else "—")
            else:
                cells.append(".")
        out.append("| " + " | ".join(cells) + " |")
    return "\n".join(out) + "\n"
