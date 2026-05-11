"""Uncertainty quantification helpers for benchmark metrics.

Two interval methods, stdlib only:

* ``wilson_score_ci`` — closed-form binomial proportion CI for rate-style
  metrics (precision, recall, citation rates). Robust at small n and at
  the 0/1 boundaries.
* ``bootstrap_metric_ci`` / ``bootstrap_prf_ci`` — percentile bootstrap
  over per-case outcomes. Use for F1 and other non-proportion metrics;
  resampling preserves the dependence structure between TP/FP/FN counts.
"""

from __future__ import annotations

import math
import random
from typing import Any, Callable, Dict, Sequence, Tuple

Outcome = Tuple[bool, bool]  # (predicted, label)


# Hardcoded common z-values avoid pulling scipy in for the typical case.
_COMMON_Z = {
    0.80: 1.2815515655446004,
    0.90: 1.6448536269514722,
    0.95: 1.959963984540054,
    0.98: 2.3263478740408408,
    0.99: 2.5758293035489004,
}


def _probit(p: float) -> float:
    """Inverse normal CDF via Acklam's approximation (~1e-9 accuracy).

    Reference: Acklam, P. J., "An algorithm for computing the inverse
    normal cumulative distribution function" (2003).
    """
    if not 0.0 < p < 1.0:
        raise ValueError("p must be in (0, 1)")
    a = (
        -3.969683028665376e01,
        2.209460984245205e02,
        -2.759285104469687e02,
        1.383577518672690e02,
        -3.066479806614716e01,
        2.506628277459239e00,
    )
    b = (
        -5.447609879822406e01,
        1.615858368580409e02,
        -1.556989798598866e02,
        6.680131188771972e01,
        -1.328068155288572e01,
    )
    c = (
        -7.784894002430293e-03,
        -3.223964580411365e-01,
        -2.400758277161838e00,
        -2.549732539343734e00,
        4.374664141464968e00,
        2.938163982698783e00,
    )
    d = (
        7.784695709041462e-03,
        3.224671290700398e-01,
        2.445134137142996e00,
        3.754408661907416e00,
    )
    plow = 0.02425
    phigh = 1 - plow
    if p < plow:
        q = math.sqrt(-2 * math.log(p))
        return (((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5]) / (
            (((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1
        )
    if p <= phigh:
        q = p - 0.5
        r = q * q
        return (
            (((((a[0] * r + a[1]) * r + a[2]) * r + a[3]) * r + a[4]) * r + a[5]) * q
        ) / (((((b[0] * r + b[1]) * r + b[2]) * r + b[3]) * r + b[4]) * r + 1)
    q = math.sqrt(-2 * math.log(1 - p))
    return -(
        ((((c[0] * q + c[1]) * q + c[2]) * q + c[3]) * q + c[4]) * q + c[5]
    ) / ((((d[0] * q + d[1]) * q + d[2]) * q + d[3]) * q + 1)


def _two_sided_z(confidence: float) -> float:
    if not 0.0 < confidence < 1.0:
        raise ValueError("confidence must be in (0, 1)")
    if confidence in _COMMON_Z:
        return _COMMON_Z[confidence]
    return _probit((1 + confidence) / 2)


def wilson_score_ci(
    successes: int,
    trials: int,
    *,
    confidence: float = 0.95,
) -> Dict[str, Any]:
    """Wilson score interval for a binomial proportion.

    Returns a dict with ``point``, ``ci_low``, ``ci_high``, ``n``, ``method``,
    ``confidence``. When ``trials == 0`` returns the conservative [0, 1].
    """
    if trials < 0:
        raise ValueError("trials must be >= 0")
    if successes < 0 or successes > trials:
        raise ValueError("successes must be in [0, trials]")
    if trials == 0:
        return {
            "point": 0.0,
            "ci_low": 0.0,
            "ci_high": 1.0,
            "n": 0,
            "method": "wilson",
            "confidence": confidence,
        }

    z = _two_sided_z(confidence)
    p = successes / trials
    z2 = z * z
    denom = 1 + z2 / trials
    center = (p + z2 / (2 * trials)) / denom
    half = z * math.sqrt(p * (1 - p) / trials + z2 / (4 * trials * trials)) / denom
    ci_low = max(0.0, center - half)
    ci_high = min(1.0, center + half)
    if successes == 0:
        ci_low = 0.0
    if successes == trials:
        ci_high = 1.0
    return {
        "point": p,
        "ci_low": ci_low,
        "ci_high": ci_high,
        "n": trials,
        "method": "wilson",
        "confidence": confidence,
    }


def precision_from_outcomes(outcomes: Sequence[Outcome]) -> float:
    tp = sum(1 for predicted, label in outcomes if predicted and label)
    fp = sum(1 for predicted, label in outcomes if predicted and not label)
    return tp / (tp + fp) if (tp + fp) > 0 else 0.0


def recall_from_outcomes(outcomes: Sequence[Outcome]) -> float:
    tp = sum(1 for predicted, label in outcomes if predicted and label)
    fn = sum(1 for predicted, label in outcomes if not predicted and label)
    return tp / (tp + fn) if (tp + fn) > 0 else 0.0


def f1_from_outcomes(outcomes: Sequence[Outcome]) -> float:
    p = precision_from_outcomes(outcomes)
    r = recall_from_outcomes(outcomes)
    return (2 * p * r / (p + r)) if (p + r) > 0 else 0.0


def bootstrap_metric_ci(
    outcomes: Sequence[Any],
    metric_fn: Callable[[Sequence[Any]], float],
    *,
    n_resamples: int = 2000,
    confidence: float = 0.95,
    seed: int | None = None,
) -> Dict[str, Any]:
    """Percentile bootstrap CI for ``metric_fn`` over ``outcomes``.

    Resamples ``outcomes`` with replacement ``n_resamples`` times. The CI is the
    [α/2, 1-α/2] empirical percentile of the resampled metric distribution.

    Use this for F1 (which is not a simple proportion) and for compound metrics
    where the resampling unit is the per-case outcome.
    """
    if n_resamples <= 0:
        raise ValueError("n_resamples must be > 0")
    if not 0.0 < confidence < 1.0:
        raise ValueError("confidence must be in (0, 1)")

    n = len(outcomes)
    if n == 0:
        return {
            "point": 0.0,
            "ci_low": 0.0,
            "ci_high": 1.0,
            "n": 0,
            "method": "bootstrap_percentile",
            "n_resamples": 0,
            "confidence": confidence,
        }

    rng = random.Random(seed)
    point = float(metric_fn(outcomes))
    samples = []
    for _ in range(n_resamples):
        resampled = [outcomes[rng.randrange(n)] for _ in range(n)]
        samples.append(float(metric_fn(resampled)))
    samples.sort()
    alpha = (1 - confidence) / 2
    lo_idx = max(0, int(math.floor(alpha * n_resamples)))
    hi_idx = min(n_resamples - 1, int(math.ceil((1 - alpha) * n_resamples)) - 1)
    return {
        "point": point,
        "ci_low": samples[lo_idx],
        "ci_high": samples[hi_idx],
        "n": n,
        "method": "bootstrap_percentile",
        "n_resamples": n_resamples,
        "confidence": confidence,
        "seed": seed,
    }


def bootstrap_prf_ci(
    outcomes: Sequence[Outcome],
    *,
    n_resamples: int = 2000,
    confidence: float = 0.95,
    seed: int | None = None,
) -> Dict[str, Dict[str, Any]]:
    """Convenience: bootstrap CIs for precision, recall, and F1 from one set of
    per-case outcomes. Uses the same resamples for all three metrics so the
    intervals are jointly comparable.
    """
    if n_resamples <= 0:
        raise ValueError("n_resamples must be > 0")
    n = len(outcomes)
    if n == 0:
        zero = {
            "point": 0.0,
            "ci_low": 0.0,
            "ci_high": 1.0,
            "n": 0,
            "method": "bootstrap_percentile",
            "n_resamples": 0,
            "confidence": confidence,
        }
        return {"precision": dict(zero), "recall": dict(zero), "f1": dict(zero)}

    rng = random.Random(seed)
    p_samples, r_samples, f_samples = [], [], []
    for _ in range(n_resamples):
        resampled = [outcomes[rng.randrange(n)] for _ in range(n)]
        p_samples.append(precision_from_outcomes(resampled))
        r_samples.append(recall_from_outcomes(resampled))
        f_samples.append(f1_from_outcomes(resampled))

    alpha = (1 - confidence) / 2
    lo_idx = max(0, int(math.floor(alpha * n_resamples)))
    hi_idx = min(n_resamples - 1, int(math.ceil((1 - alpha) * n_resamples)) - 1)

    def _summary(point: float, samples: list[float]) -> Dict[str, Any]:
        samples.sort()
        return {
            "point": float(point),
            "ci_low": samples[lo_idx],
            "ci_high": samples[hi_idx],
            "n": n,
            "method": "bootstrap_percentile",
            "n_resamples": n_resamples,
            "confidence": confidence,
            "seed": seed,
        }

    return {
        "precision": _summary(precision_from_outcomes(outcomes), p_samples),
        "recall": _summary(recall_from_outcomes(outcomes), r_samples),
        "f1": _summary(f1_from_outcomes(outcomes), f_samples),
    }
