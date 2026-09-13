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
from collections.abc import Callable, Sequence
from typing import Any

Outcome = tuple[bool, bool]  # (predicted, label)


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
) -> dict[str, Any]:
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
) -> dict[str, Any]:
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
) -> dict[str, dict[str, Any]]:
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

    def _summary(point: float, samples: list[float]) -> dict[str, Any]:
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


# Paired classifier comparison — McNemar's exact test + paired bootstrap.
#
# These tests answer "is classifier B's behaviour significantly different
# from classifier A's, on the same instances?" — the canonical paired-test
# setting for SAST tool comparison.

PairedOutcome = tuple[bool, bool, bool]  # (pred_a, pred_b, label)


def _binom_pmf(k: int, n: int, p: float) -> float:
    return math.comb(n, k) * (p**k) * ((1 - p) ** (n - k))


def _binom_cdf(k: int, n: int, p: float) -> float:
    return sum(_binom_pmf(i, n, p) for i in range(0, k + 1))


def paired_classifier_mcnemar(
    paired: Sequence[PairedOutcome],
    *,
    restrict_to: str = "all",
) -> dict[str, Any]:
    """Exact-binomial McNemar's test for two paired classifiers.

    Counts discordant pairs:
        b = cases where A fires (1) and B does not (0)
        c = cases where A does not fire (0) and B fires (1)

    Under H0 — both classifiers are equally likely to err on a given case —
    ``b ~ Binomial(b + c, 0.5)``. The two-sided exact p-value is
    ``2 · min(P(X ≤ b), P(X ≥ b))`` clipped to [0, 1].

    The exact binomial form (rather than the chi-square approximation)
    handles small samples and the b + c = 0 degenerate case without a
    continuity correction.

    ``restrict_to``:
        ``"all"``  — every pair, default;
        ``"fp_class"`` — only cases where ``label`` is False (firing is bad),
            so b = "A-FP cleared by B" and c = "B-FP not in A" (regressions);
        ``"fn_class"`` — only cases where ``label`` is True (firing is needed),
            so b = "A-TP that B missed" (regressions) and c = "B-TP added".

    Returns a dict with: ``b``, ``c``, ``n_disagreements``, ``p_value``,
    ``test_defined`` (False when b + c == 0).
    """

    if restrict_to not in {"all", "fp_class", "fn_class"}:
        raise ValueError(f"restrict_to must be one of all/fp_class/fn_class, got {restrict_to!r}")

    b = 0
    c = 0
    for pred_a, pred_b, label in paired:
        if restrict_to == "fp_class" and label:
            continue
        if restrict_to == "fn_class" and not label:
            continue
        if pred_a and not pred_b:
            b += 1
        elif not pred_a and pred_b:
            c += 1

    n = b + c
    if n == 0:
        return {
            "b": b,
            "c": c,
            "n_disagreements": 0,
            "p_value": None,
            "test_defined": False,
            "restrict_to": restrict_to,
        }

    cdf_low = _binom_cdf(min(b, c), n, 0.5)
    p_value = min(1.0, 2.0 * cdf_low)
    return {
        "b": b,
        "c": c,
        "n_disagreements": n,
        "p_value": p_value,
        "test_defined": True,
        "restrict_to": restrict_to,
    }


def _fpr(outcomes: Sequence[Outcome]) -> float:
    fp = sum(1 for predicted, label in outcomes if predicted and not label)
    tn = sum(1 for predicted, label in outcomes if not predicted and not label)
    return fp / (fp + tn) if (fp + tn) > 0 else 0.0


def _fnr(outcomes: Sequence[Outcome]) -> float:
    fn = sum(1 for predicted, label in outcomes if not predicted and label)
    tp = sum(1 for predicted, label in outcomes if predicted and label)
    return fn / (fn + tp) if (fn + tp) > 0 else 0.0


def bootstrap_paired_delta_ci(
    paired: Sequence[PairedOutcome],
    *,
    metric: str,
    n_resamples: int = 2000,
    confidence: float = 0.95,
    seed: int | None = None,
) -> dict[str, Any]:
    """Paired bootstrap CI for the *delta* in a per-case rate metric.

    ``paired`` is a sequence of ``(pred_a, pred_b, label)`` triples — the
    same per-case structure as for McNemar. Each bootstrap resample picks
    cases with replacement and computes ``metric(B) - metric(A)`` on the
    resampled set. The percentile CI is reported alongside the point
    estimate.

    ``metric`` ∈ {``"fpr"``, ``"fnr"``}. FPR uses NEG cases only, FNR
    uses POS cases only. Cases that don't contribute (e.g. POS cases when
    computing FPR) still appear in the resample; the metric simply ignores
    them in the denominator.
    """

    if metric not in {"fpr", "fnr"}:
        raise ValueError(f"metric must be 'fpr' or 'fnr', got {metric!r}")
    if n_resamples <= 0:
        raise ValueError("n_resamples must be > 0")
    if not 0.0 < confidence < 1.0:
        raise ValueError("confidence must be in (0, 1)")

    fn = _fpr if metric == "fpr" else _fnr
    outcomes_a = [(p_a, label) for p_a, _p_b, label in paired]
    outcomes_b = [(p_b, label) for _p_a, p_b, label in paired]
    point = fn(outcomes_b) - fn(outcomes_a)

    n = len(paired)
    if n == 0:
        return {
            "metric": f"delta_{metric}",
            "point": 0.0,
            "ci_low": 0.0,
            "ci_high": 0.0,
            "n": 0,
            "method": "bootstrap_percentile",
            "n_resamples": 0,
            "confidence": confidence,
            "seed": seed,
        }

    rng = random.Random(seed)
    samples: list[float] = []
    for _ in range(n_resamples):
        idxs = [rng.randrange(n) for _ in range(n)]
        resamp_a = [outcomes_a[i] for i in idxs]
        resamp_b = [outcomes_b[i] for i in idxs]
        samples.append(fn(resamp_b) - fn(resamp_a))
    samples.sort()
    alpha = (1 - confidence) / 2
    lo_idx = max(0, int(math.floor(alpha * n_resamples)))
    hi_idx = min(n_resamples - 1, int(math.ceil((1 - alpha) * n_resamples)) - 1)
    return {
        "metric": f"delta_{metric}",
        "point": point,
        "ci_low": samples[lo_idx],
        "ci_high": samples[hi_idx],
        "n": n,
        "method": "bootstrap_percentile",
        "n_resamples": n_resamples,
        "confidence": confidence,
        "seed": seed,
    }
