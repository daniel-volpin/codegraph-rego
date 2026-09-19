from __future__ import annotations

import math
import random
from collections.abc import Callable, Sequence
from typing import Any

from codegraph.evaluation.uncertainty_proportions import (
    Outcome,
    f1_from_outcomes,
    precision_from_outcomes,
    recall_from_outcomes,
)

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
    """Exact-binomial McNemar's test for two paired classifiers."""
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


def bootstrap_metric_ci(
    outcomes: Sequence[Any],
    metric_fn: Callable[[Sequence[Any]], float],
    *,
    n_resamples: int = 2000,
    confidence: float = 0.95,
    seed: int | None = None,
) -> dict[str, Any]:
    """Percentile bootstrap CI for ``metric_fn`` over ``outcomes``."""
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


def bootstrap_paired_delta_ci(
    paired: Sequence[PairedOutcome],
    *,
    metric: str,
    n_resamples: int = 2000,
    confidence: float = 0.95,
    seed: int | None = None,
) -> dict[str, Any]:
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
