"""
Trace aggregation and reporting script for CodeGraph OTel span output.

Reads spans emitted by ConsoleSpanExporter (or OTEL_TRACE_FILE) and
produces a Markdown summary with token usage, latency, fix outcomes,
retry overhead, and top errors.

Usage
-----
# From a saved trace file (recommended — use OTEL_TRACE_FILE=... during the run):
python scripts/evaluation/report_traces.py traces.jsonl

# From a captured run (stdout redirect):
python run_remediation_eval.py ... > traces.jsonl 2>run.log
python scripts/evaluation/report_traces.py traces.jsonl

# From stdin:
python run_remediation_eval.py ... | python scripts/evaluation/report_traces.py

# JSON output:
python scripts/evaluation/report_traces.py traces.jsonl --json
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


# ── Span parsing ──────────────────────────────────────────────────────────────


def _parse_iso(ts: str | None) -> datetime | None:
    if not ts:
        return None
    # OTel SDK emits e.g. "2026-03-22T14:03:10.123456Z"
    ts = ts.rstrip("Z").split("+")[0]
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(ts, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _duration_ms(span: dict[str, Any]) -> float | None:
    start = _parse_iso(span.get("start_time"))
    end = _parse_iso(span.get("end_time"))
    if start and end:
        return (end - start).total_seconds() * 1000
    return None


def load_spans(source) -> list[dict[str, Any]]:
    """Read JSON span objects from *source* (file-like), skipping non-JSON lines."""
    spans: list[dict[str, Any]] = []
    for raw in source:
        line = raw.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict) and "name" in obj:
                spans.append(obj)
        except json.JSONDecodeError:
            pass
    return spans


# ── Section builders ──────────────────────────────────────────────────────────


def _attr(span: dict[str, Any], key: str, default=None):
    return (span.get("attributes") or {}).get(key, default)


def _section_run_summary(by_name: dict[str, list]) -> list[str]:
    lines: list[str] = []
    run_spans = by_name.get("benchmark.run", [])
    if run_spans:
        s = run_spans[-1]  # last = most recent run
        lines += [
            f"Config      : {_attr(s, 'config_name', '—')}",
            f"Mode        : {_attr(s, 'mode', '—')}",
            f"Sample size : {_attr(s, 'sample_size', '—')}",
            f"Model       : {_attr(s, 'model') or _attr(s, 'remediation_model') or '—'}",
            f"Total cases : {_attr(s, 'total_cases', len(by_name.get('benchmark.case', [])))}",
            f"Final status: {_attr(s, 'final_status', '—')}",
        ]
    else:
        cases = len(by_name.get("benchmark.case", []))
        lines.append(f"Total cases : {cases}  (no benchmark.run span found)")
    return lines


def _section_tokens(by_name: dict[str, list]) -> list[str]:
    llm_spans = by_name.get("llm.generate", [])
    if not llm_spans:
        return ["  (no llm.generate spans found)"]

    def valid_tokens(spans, key: str) -> list[int]:
        return [_attr(s, key) for s in spans if (_attr(s, key) or -1) > 0]

    total_prompt = sum(valid_tokens(llm_spans, "llm.prompt_tokens"))
    total_completion = sum(valid_tokens(llm_spans, "llm.completion_tokens"))
    total_all = sum(valid_tokens(llm_spans, "llm.total_tokens"))
    case_count = len(by_name.get("benchmark.case", [])) or 1

    # Retry overhead: spans where retry_index > 0
    retry_spans = [s for s in llm_spans if (_attr(s, "llm.retry_index") or 0) > 0]
    retry_tokens = sum(valid_tokens(retry_spans, "llm.total_tokens"))
    retry_pct = (retry_tokens / total_all * 100) if total_all > 0 else 0.0

    # By task_type
    by_type: dict[str, int] = defaultdict(int)
    for s in llm_spans:
        tt = _attr(s, "llm.task_type") or "unknown"
        t = _attr(s, "llm.total_tokens") or -1
        if t > 0:
            by_type[tt] += t

    lines = [
        f"  Total       : {total_all:,}  "
        f"(prompt {total_prompt:,} | completion {total_completion:,})",
        f"  Per case    : {total_all // case_count:,}  (avg)",
        f"  Retry waste : {retry_tokens:,}  ({retry_pct:.1f}% of total)",
    ]
    if by_type:
        lines.append("  By task_type:")
        for tt, tok in sorted(by_type.items(), key=lambda x: -x[1]):
            pct = tok / total_all * 100 if total_all else 0
            lines.append(f"    {tt:<16} {tok:>10,}  ({pct:.1f}%)")
    return lines


def _percentiles(values: list[float]) -> str:
    if not values:
        return "n/a"
    p50 = statistics.median(values)
    p95 = sorted(values)[int(len(values) * 0.95)]
    mx = max(values)
    return f"p50 {p50:,.0f} ms | p95 {p95:,.0f} ms | max {mx:,.0f} ms"


def _section_llm_latency(by_name: dict[str, list]) -> list[str]:
    spans = by_name.get("llm.generate", [])
    latencies = [_attr(s, "llm.latency_ms") for s in spans if _attr(s, "llm.latency_ms")]
    if not latencies:
        return ["  (no latency data)"]
    return [
        f"  Calls  : {len(latencies)}",
        f"  {_percentiles(latencies)}",
    ]


def _section_build_latency(by_name: dict[str, list]) -> list[str]:
    spans = by_name.get("build.verify", [])
    if not spans:
        return ["  (no build.verify spans found)"]

    attempted = [s for s in spans if not _attr(s, "build_skipped", False)]
    skipped = len(spans) - len(attempted)
    successes = sum(1 for s in attempted if _attr(s, "build_success", False))

    # Prefer the explicit attribute; fall back to computed duration.
    durations = []
    for s in attempted:
        d = _attr(s, "build_duration_ms")
        if d is None:
            d = _duration_ms(s)
        if d is not None:
            durations.append(float(d))

    lines = [
        f"  Attempted : {len(attempted)}  |  Skipped : {skipped}  |  Passed : {successes}",
    ]
    if durations:
        lines.append(f"  {_percentiles(durations)}")
    return lines


def _section_fix_outcomes(by_name: dict[str, list]) -> list[str]:
    spans = by_name.get("remediation.fix", [])
    if not spans:
        return ["  (no remediation.fix spans found)"]

    counts: Counter = Counter(_attr(s, "final_status") or "unknown" for s in spans)
    total = len(spans)
    lines = []
    for status, count in counts.most_common():
        pct = count / total * 100
        lines.append(f"  {status:<30} {count:>4}  ({pct:.0f}%)")
    return lines


def _section_attempt_quality(by_name: dict[str, list]) -> list[str]:
    spans = by_name.get("remediation.attempt", [])
    if not spans:
        return ["  (no remediation.attempt spans found)"]

    valid = sum(1 for s in spans if _attr(s, "schema_valid", False))
    pct = valid / len(spans) * 100

    errors: list[str] = [
        _attr(s, "error_summary", "").strip()
        for s in spans
        if _attr(s, "error_summary", "").strip()
    ]
    top_errors = Counter(errors).most_common(5)

    lines = [f"  Schema valid : {valid}/{len(spans)}  ({pct:.1f}%)"]
    if top_errors:
        lines.append("  Top errors:")
        for err, cnt in top_errors:
            snippet = err[:80] + ("…" if len(err) > 80 else "")
            lines.append(f"    ({cnt}×) {snippet}")
    return lines


def _section_slowest_spans(spans: list[dict[str, Any]], top_n: int = 8) -> list[str]:
    rows: list[tuple[float, str]] = []
    for s in spans:
        # Use explicit latency_ms attribute when available (llm.generate)
        d = _attr(s, "llm.latency_ms") or _attr(s, "build_duration_ms") or _duration_ms(s)
        if d:
            rows.append((float(d), s["name"]))

    if not rows:
        return ["  (no duration data)"]

    rows.sort(reverse=True)
    lines = []
    for dur, name in rows[:top_n]:
        lines.append(f"  {name:<35} {dur:>10,.0f} ms")
    return lines


# ── Report assembly ───────────────────────────────────────────────────────────


def build_report(spans: list[dict[str, Any]]) -> str:
    by_name: dict[str, list] = defaultdict(list)
    for s in spans:
        by_name[s["name"]].append(s)

    ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    sections = [f"# CodeGraph Trace Report — {ts}\n"]

    sections.append("## Run Summary")
    sections.extend(_section_run_summary(by_name))

    sections.append("\n## Token Usage")
    sections.extend(_section_tokens(by_name))

    sections.append("\n## LLM Latency  (llm.generate)")
    sections.extend(_section_llm_latency(by_name))

    sections.append("\n## Build Verification  (build.verify)")
    sections.extend(_section_build_latency(by_name))

    sections.append("\n## Fix Outcomes  (remediation.fix)")
    sections.extend(_section_fix_outcomes(by_name))

    sections.append("\n## Attempt Quality  (remediation.attempt)")
    sections.extend(_section_attempt_quality(by_name))

    sections.append(f"\n## Slowest Individual Spans  (top {8})")
    sections.extend(_section_slowest_spans(spans))

    sections.append(f"\n---\n_{len(spans)} spans parsed_")
    return "\n".join(sections) + "\n"


def build_json_report(spans: list[dict[str, Any]]) -> dict[str, Any]:
    by_name: dict[str, list] = defaultdict(list)
    for s in spans:
        by_name[s["name"]].append(s)

    def valid_tokens(ss, key):
        return [_attr(s, key) for s in ss if (_attr(s, key) or -1) > 0]

    llm = by_name.get("llm.generate", [])
    total_tokens = sum(valid_tokens(llm, "llm.total_tokens"))
    retry_spans = [s for s in llm if (_attr(s, "llm.retry_index") or 0) > 0]
    retry_tokens = sum(valid_tokens(retry_spans, "llm.total_tokens"))

    build_spans = [s for s in by_name.get("build.verify", []) if not _attr(s, "build_skipped", False)]
    build_durations = [
        float(_attr(s, "build_duration_ms") or _duration_ms(s) or 0)
        for s in build_spans
    ]
    fix_statuses = Counter(_attr(s, "final_status") or "unknown" for s in by_name.get("remediation.fix", []))
    attempt_spans = by_name.get("remediation.attempt", [])

    return {
        "total_spans": len(spans),
        "tokens": {
            "total": total_tokens,
            "prompt": sum(valid_tokens(llm, "llm.prompt_tokens")),
            "completion": sum(valid_tokens(llm, "llm.completion_tokens")),
            "retry_overhead": retry_tokens,
            "by_task_type": dict(
                Counter(
                    _attr(s, "llm.task_type") or "unknown"
                    for s in llm
                    for _ in [1]
                    if (_attr(s, "llm.total_tokens") or -1) > 0
                )
            ),
        },
        "build_verify": {
            "attempted": len(build_spans),
            "passed": sum(1 for s in build_spans if _attr(s, "build_success", False)),
            "duration_ms": {
                "p50": statistics.median(build_durations) if build_durations else None,
                "p95": sorted(build_durations)[int(len(build_durations) * 0.95)] if build_durations else None,
                "max": max(build_durations) if build_durations else None,
            },
        },
        "fix_outcomes": dict(fix_statuses),
        "attempt_quality": {
            "total": len(attempt_spans),
            "schema_valid": sum(1 for s in attempt_spans if _attr(s, "schema_valid", False)),
        },
    }


# ── CLI ───────────────────────────────────────────────────────────────────────


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Summarise CodeGraph OTel trace output into a Markdown or JSON report.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "trace_file",
        nargs="?",
        help="Path to JSONL trace file (default: read from stdin)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of Markdown",
    )
    args = parser.parse_args()

    if args.trace_file:
        source = Path(args.trace_file).open(encoding="utf-8")
    else:
        source = sys.stdin

    spans = load_spans(source)
    if not spans:
        print("No spans found in input.", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(build_json_report(spans), indent=2))
    else:
        print(build_report(spans))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
