"""Confidence calibration, reliability diagrams, and risk-coverage curves."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from codegraph.evaluation.io import render_markdown_table

ATTEMPTED_REMEDIATION_STATUSES: Sequence[str] = (
    "OK",
    "GENERATION_ERROR",
    "REPLACEMENT_ERROR",
    "BUILD_ERROR",
    "VERIFICATION_ERROR",
)

FULLY_VERIFIED_LABEL_DEFINITION = "fully_verified := policy_fixed is true and build_success is true"


def _safe_float(value: Any) -> float | None:
    try:
        number = float(value)
    except TypeError, ValueError:
        return None
    if number < 0.0 or number > 1.0:
        return None
    return number


def is_fully_verified(item: Mapping[str, Any]) -> bool:
    value = item.get("fully_verified")
    if isinstance(value, bool):
        return value
    return item.get("policy_fixed") is True and item.get("build_success") is True


def _calibration_block(
    points: list[tuple[float, int]],
    cases: list[dict[str, Any]],
    missing_confidence_count: int,
    *,
    bins: int,
    population: str,
) -> dict[str, Any] | None:
    if not points:
        return None

    n = len(points)
    brier_score = sum((score - label) ** 2 for score, label in points) / n

    bucket_count = max(1, bins)
    buckets: list[list[tuple[float, int]]] = [[] for _ in range(bucket_count)]
    for score, label in points:
        index = min(int(score * bucket_count), bucket_count - 1)
        buckets[index].append((score, label))

    ece = 0.0
    reliability_bins: list[dict[str, Any]] = []
    for idx, bucket in enumerate(buckets):
        if not bucket:
            continue
        count = len(bucket)
        avg_confidence = sum(score for score, _ in bucket) / count
        empirical_success = sum(label for _, label in bucket) / count
        gap = abs(avg_confidence - empirical_success)
        ece += (count / n) * gap
        reliability_bins.append(
            {
                "bin_start": round(idx / bucket_count, 4),
                "bin_end": round((idx + 1) / bucket_count, 4),
                "count": count,
                "avg_confidence": round(avg_confidence, 4),
                "empirical_success": round(empirical_success, 4),
                "gap": round(gap, 4),
            }
        )

    ranked = sorted(points, key=lambda pair: pair[0], reverse=True)
    checkpoints = [0.25, 0.5, 0.75, 1.0]
    risk_coverage: list[dict[str, Any]] = []
    for checkpoint in checkpoints:
        k = max(1, int(round(n * checkpoint)))
        subset = ranked[:k]
        success_rate = sum(label for _, label in subset) / k
        risk_coverage.append(
            {
                "coverage": round(k / n, 4),
                "success_rate": round(success_rate, 4),
                "risk": round(1.0 - success_rate, 4),
            }
        )

    return {
        "population": population,
        "count": n,
        "missing_confidence_count": missing_confidence_count,
        "label": "fully_verified",
        "label_definition": FULLY_VERIFIED_LABEL_DEFINITION,
        "positive_count": sum(label for _, label in points),
        "negative_count": n - sum(label for _, label in points),
        "brier_score": round(brier_score, 6),
        "ece": round(ece, 6),
        "reliability_bins": reliability_bins,
        "risk_coverage": risk_coverage,
        "cases": cases,
    }


def _collect_calibration_points(
    results: Sequence[Mapping[str, Any]],
    *,
    status_filter: set[str] | None = None,
) -> tuple[list[tuple[float, int]], list[dict[str, Any]], int]:
    points: list[tuple[float, int]] = []
    cases: list[dict[str, Any]] = []
    missing_confidence_count = 0
    for item in results:
        if status_filter is not None:
            status = str(item.get("status") or "")
            if status not in status_filter:
                continue
        confidence = item.get("confidence") or {}
        score = _safe_float((confidence or {}).get("score"))
        if score is None:
            missing_confidence_count += 1
            continue
        label = 1 if is_fully_verified(item) else 0
        points.append((score, label))
        cases.append(
            {
                "case_id": item.get("case_id"),
                "violation_id": item.get("violation_id"),
                "status": item.get("status"),
                "confidence_score": score,
                "confidence_band": confidence.get("band"),
                "fully_verified": bool(label),
                "policy_fixed": item.get("policy_fixed"),
                "build_success": item.get("build_success"),
            }
        )
    return points, cases, missing_confidence_count


def build_confidence_calibration(
    results: Sequence[Mapping[str, Any]],
    *,
    bins: int = 10,
) -> dict[str, Any] | None:
    """Compute confidence calibration over the remediation results."""
    full_points, full_cases, full_missing = _collect_calibration_points(results)
    full = _calibration_block(full_points, full_cases, full_missing, bins=bins, population="full")
    if full is None:
        return None

    attempted_filter = set(ATTEMPTED_REMEDIATION_STATUSES)
    a_points, a_cases, a_missing = _collect_calibration_points(results, status_filter=attempted_filter)
    attempted = _calibration_block(a_points, a_cases, a_missing, bins=bins, population="attempted_only")

    n_points, n_cases, n_missing = _collect_calibration_points(results, status_filter={"NO_FIX"})
    no_fix = _calibration_block(n_points, n_cases, n_missing, bins=bins, population="no_fix_only")

    return {
        **full,
        "populations": {
            "full": full,
            "attempted_only": attempted,
            "no_fix_only": no_fix,
        },
    }


def render_calibration_markdown(calibration: Mapping[str, Any]) -> str:
    lines = [
        "# Remediation Calibration",
        "",
        "Headline numbers below are computed over the **full** population (every "
        "result that carries a confidence score, including `NO_FIX` abstentions). "
        "The per-population breakdown distinguishes calibrated success "
        "probability from knew-when-to-abstain behavior.",
        "",
        f"- Cases with confidence: `{calibration.get('count', 0)}`",
        f"- Missing confidence: `{calibration.get('missing_confidence_count', 0)}`",
        f"- Label: `{calibration.get('label', 'fully_verified')}`",
        f"- Label definition: `{calibration.get('label_definition', FULLY_VERIFIED_LABEL_DEFINITION)}`",
        f"- Positive labels: `{calibration.get('positive_count', 0)}`",
        f"- Negative labels: `{calibration.get('negative_count', 0)}`",
        f"- Brier score (full): `{calibration.get('brier_score', 'n/a')}`",
        f"- ECE (full): `{calibration.get('ece', 'n/a')}`",
        "",
        "## Reliability Bins (full population)",
        "",
        render_markdown_table(
            ["Bin", "Count", "Avg confidence", "Empirical success", "Gap"],
            [
                [
                    f"{item.get('bin_start')}-{item.get('bin_end')}",
                    item.get("count"),
                    item.get("avg_confidence"),
                    item.get("empirical_success"),
                    item.get("gap"),
                ]
                for item in calibration.get("reliability_bins", [])
            ],
        ).rstrip(),
    ]

    populations = calibration.get("populations") if isinstance(calibration, Mapping) else None
    if isinstance(populations, Mapping):
        rows = []
        for name in ("full", "attempted_only", "no_fix_only"):
            block = populations.get(name)
            if not isinstance(block, Mapping):
                rows.append([name, "0", "n/a", "n/a", "n/a", "n/a"])
                continue
            rows.append(
                [
                    name,
                    block.get("count", 0),
                    block.get("positive_count", 0),
                    block.get("negative_count", 0),
                    block.get("brier_score", "n/a"),
                    block.get("ece", "n/a"),
                ]
            )
        lines.extend(
            [
                "",
                "## Calibration by Population",
                "",
                render_markdown_table(
                    ["Population", "Count", "Positive", "Negative", "Brier", "ECE"],
                    rows,
                ).rstrip(),
                "",
                "Population definitions:",
                "- `full`: every result with a confidence score (legacy headline).",
                "- `attempted_only`: results where the system attempted to apply a"
                " remediation (status in OK / GENERATION_ERROR / REPLACEMENT_ERROR /"
                " BUILD_ERROR / VERIFICATION_ERROR).",
                "- `no_fix_only`: declared-abstention cases (status NO_FIX).",
            ]
        )

    return "\n".join(lines) + "\n"
