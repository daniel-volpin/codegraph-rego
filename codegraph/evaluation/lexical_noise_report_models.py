from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field
from typing import Any

from codegraph.evaluation.uncertainty import bootstrap_prf_ci

METHODS = ("pre_f10", "post_f10", "semgrep")
SEMGREP_REGISTRY_METHOD = "semgrep_registry"


def report_methods(report: EvalReport) -> tuple[str, ...]:
    """Canonical method order for ``report`` — known METHODS first, extras after."""
    known = [m for m in METHODS if m in report.metrics]
    extras = [m for m in report.metrics if m not in METHODS]
    return tuple(known + extras)


@dataclass(frozen=True)
class DetectionResult:
    """One method's verdict on one case."""

    case_id: str
    method: str  # "pre_f10" | "post_f10" | "semgrep"
    fired_violation_ids: tuple[str, ...]
    target_fired: bool


@dataclass(frozen=True)
class CaseRow:
    case_id: str
    file_name: str
    fp_source: str
    expected: str
    target_violation_ids: tuple[str, ...]
    by_method: Mapping[str, DetectionResult]


@dataclass(frozen=True)
class MethodMetrics:
    name: str
    tp: int
    fp: int
    tn: int
    fn: int
    precision: float
    recall: float
    f1: float
    bootstrap: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_outcomes(
        cls,
        name: str,
        outcomes: Sequence[tuple[bool, bool]],
        *,
        n_resamples: int = 2000,
        seed: int = 0,
    ) -> MethodMetrics:
        tp = sum(1 for pred, label in outcomes if pred and label)
        fp = sum(1 for pred, label in outcomes if pred and not label)
        tn = sum(1 for pred, label in outcomes if not pred and not label)
        fn = sum(1 for pred, label in outcomes if not pred and label)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
        bootstrap = bootstrap_prf_ci(outcomes, n_resamples=n_resamples, seed=seed)
        return cls(
            name=name,
            tp=tp,
            fp=fp,
            tn=tn,
            fn=fn,
            precision=precision,
            recall=recall,
            f1=f1,
            bootstrap=bootstrap,
        )


@dataclass(frozen=True)
class StratumMetrics:
    """Metrics for one ``fp_source`` stratum (e.g. ``line_comment``)."""

    stratum: str
    n_cases: int
    n_positive: int
    n_negative: int
    methods: Mapping[str, MethodMetrics]


@dataclass(frozen=True)
class PairedComparison:
    """Paired classifier comparison: McNemar's exact + ΔFPR / ΔFNR CIs."""

    method_a: str
    method_b: str
    scope: str  # "overall" | "fp_class" | per-stratum name
    mcnemar: Mapping[str, Any]
    delta_fpr: Mapping[str, Any]
    delta_fnr: Mapping[str, Any]


@dataclass(frozen=True)
class EvalReport:
    benchmark_id: str
    n_cases: int
    rows: tuple[CaseRow, ...]
    metrics: Mapping[str, MethodMetrics]
    per_stratum: Mapping[str, StratumMetrics] = field(default_factory=dict)
    paired: tuple[PairedComparison, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "benchmark_id": self.benchmark_id,
            "n_cases": self.n_cases,
            "metrics": {
                name: {
                    **{k: v for k, v in asdict(m).items() if k != "bootstrap"},
                    "bootstrap": dict(m.bootstrap),
                }
                for name, m in self.metrics.items()
            },
            "per_stratum": {
                stratum: {
                    "stratum": s.stratum,
                    "n_cases": s.n_cases,
                    "n_positive": s.n_positive,
                    "n_negative": s.n_negative,
                    "methods": {
                        name: {
                            **{k: v for k, v in asdict(m).items() if k != "bootstrap"},
                            "bootstrap": dict(m.bootstrap),
                        }
                        for name, m in s.methods.items()
                    },
                }
                for stratum, s in self.per_stratum.items()
            },
            "paired": [
                {
                    "method_a": p.method_a,
                    "method_b": p.method_b,
                    "scope": p.scope,
                    "mcnemar": dict(p.mcnemar),
                    "delta_fpr": dict(p.delta_fpr),
                    "delta_fnr": dict(p.delta_fnr),
                }
                for p in self.paired
            ],
            "rows": [
                {
                    "case_id": row.case_id,
                    "file_name": row.file_name,
                    "fp_source": row.fp_source,
                    "expected": row.expected,
                    "target_violation_ids": list(row.target_violation_ids),
                    "by_method": {
                        method: {
                            "fired_violation_ids": list(row.by_method[method].fired_violation_ids),
                            "target_fired": row.by_method[method].target_fired,
                        }
                        for method in METHODS
                        if method in row.by_method
                    },
                }
                for row in self.rows
            ],
        }
