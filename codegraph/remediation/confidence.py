from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Literal


ConfidenceBand = Literal["apply", "review", "abstain"]


@dataclass(frozen=True)
class ConfidenceAssessment:
    score: float
    band: ConfidenceBand
    threshold_apply: float
    threshold_review: float
    rationale: str


@dataclass(frozen=True)
class ConfidenceFeatures:
    support_tier: str
    decision: str
    structured_valid: bool
    has_exact_method_source: bool
    has_graph_context: bool
    attempt_count: int


def _sigmoid(value: float) -> float:
    # Clamp to avoid overflow while preserving monotonicity.
    value = max(min(value, 40.0), -40.0)
    return 1.0 / (1.0 + math.exp(-value))


def assess_remediation_confidence(
    features: ConfidenceFeatures,
    *,
    threshold_apply: float,
    threshold_review: float,
    temperature: float,
) -> ConfidenceAssessment:
    """Estimate confidence that a generated remediation is safe to auto-apply.

    This is intentionally lightweight and deterministic for thesis reproducibility.
    """

    tier = (features.support_tier or "manual").strip().lower()
    decision = (features.decision or "").strip().lower()

    z = -0.4

    if tier == "full":
        z += 1.1
    elif tier == "guarded":
        z += 0.2
    else:
        z -= 1.0

    if decision == "apply_edits":
        z += 0.8
    elif decision == "no_fix":
        z -= 2.0

    if features.structured_valid:
        z += 0.9
    else:
        z -= 0.9

    if features.has_exact_method_source:
        z += 0.4

    if features.has_graph_context:
        z += 0.2

    retries = max(features.attempt_count - 1, 0)
    if retries:
        z -= 0.7 * retries

    temp = temperature if temperature > 0 else 1.0
    score = _sigmoid(z / temp)

    if score >= threshold_apply:
        band: ConfidenceBand = "apply"
    elif score >= threshold_review:
        band = "review"
    else:
        band = "abstain"

    rationale = (
        f"tier={tier}; decision={decision or 'unknown'}; structured_valid={features.structured_valid}; "
        f"attempts={features.attempt_count}; score={score:.3f}"
    )

    return ConfidenceAssessment(
        score=round(score, 4),
        band=band,
        threshold_apply=threshold_apply,
        threshold_review=threshold_review,
        rationale=rationale,
    )
