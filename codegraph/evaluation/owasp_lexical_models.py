from __future__ import annotations

import csv
import os
import random
import subprocess
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from codegraph.evaluation.lexical_noise_report_models import (
    METHODS,
    DetectionResult,
    MethodMetrics,
    PairedComparison,
)


def _build_cwe_to_iso_map() -> dict[str, str]:
    mapping: dict[str, str] = {}
    try:
        from codegraph.benchmark_registry import load_policy_registry

        for cat in load_policy_registry().categories:
            if not cat.framework_demo:
                continue
            for cwe_str in cat.cwes:
                cwe_num = str(cwe_str).upper().replace("CWE-", "").strip()
                if cat.rego_rule_ids:
                    mapping[cwe_num] = cat.rego_rule_ids[0]
    except Exception:
        pass
    if not mapping:
        mapping = {
            "22": "ISO-A.8-PATH-TRAVERSAL",
            "78": "ISO-A.8-CMD-INJECTION",
            "89": "ISO-A.8-SQL-INJECTION",
            "90": "ISO-A.8-LDAP-INJECTION",
            "327": "ISO-A.10-WEAK-CRYPTO",
            "328": "ISO-A.10-WEAK-HASH",
            "330": "ISO-A.10-WEAK-RANDOM",
            "643": "ISO-A.8-XPATH-INJECTION",
        }
    return mapping


CWE_TO_ISO: dict[str, str] = _build_cwe_to_iso_map()
SUPPORTED_CWES: frozenset[str] = frozenset(CWE_TO_ISO.keys())

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_OWASP_CACHE = _PROJECT_ROOT / ".benchmark_cache" / "owasp-benchmark"
_FALLBACK_OWASP_TMP = Path("/tmp/owasp-benchmark")
_OWASP_GROUND_TRUTH_BASENAME = "expectedresults-1.2.csv"


def resolve_owasp_root(explicit: Path | None = None) -> Path | None:
    """Locate an OWASP Benchmark v1.2 checkout."""
    candidates: list[Path] = []
    if explicit is not None:
        candidates.append(explicit)
    env = os.environ.get("OWASP_BENCHMARK_ROOT")
    if env:
        candidates.append(Path(env))
    candidates.append(_DEFAULT_OWASP_CACHE)
    candidates.append(_FALLBACK_OWASP_TMP)
    for c in candidates:
        if c.is_dir() and (c / _OWASP_GROUND_TRUTH_BASENAME).is_file():
            return c
    return None


def owasp_paths(owasp_root: Path) -> tuple[Path, Path]:
    """Return ``(ground_truth_csv, java_testcode_root)`` under ``owasp_root``."""
    csv_path = owasp_root / _OWASP_GROUND_TRUTH_BASENAME
    java_root = owasp_root / "src" / "main" / "java" / "org" / "owasp" / "benchmark" / "testcode"
    return csv_path, java_root


def owasp_corpus_sha(owasp_root: Path) -> str | None:
    """Return the OWASP checkout's git HEAD SHA, or ``None`` if not a git repo."""
    git_dir = owasp_root / ".git"
    if not git_dir.exists():
        return None
    try:
        result = subprocess.run(
            ["git", "-C", str(owasp_root), "rev-parse", "HEAD"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5.0,
        )
    except OSError, subprocess.TimeoutExpired:
        return None
    if result.returncode != 0:
        return None
    sha = result.stdout.strip()
    return sha if sha else None


@dataclass(frozen=True)
class OwaspCase:
    test_name: str
    category: str
    real_vulnerability: bool
    cwe: str
    java_path: Path

    @property
    def target_violation_id(self) -> str:
        return CWE_TO_ISO[self.cwe]


@dataclass(frozen=True)
class OwaspCaseRow:
    case: OwaspCase
    by_method: Mapping[str, DetectionResult]


@dataclass(frozen=True)
class OwaspEvalReport:
    benchmark_id: str
    n_cases: int
    cwes_evaluated: tuple[str, ...]
    rows: tuple[OwaspCaseRow, ...]
    overall: Mapping[str, MethodMetrics]
    per_cwe: Mapping[str, Mapping[str, MethodMetrics]]
    paired: tuple[PairedComparison, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "benchmark_id": self.benchmark_id,
            "n_cases": self.n_cases,
            "cwes_evaluated": list(self.cwes_evaluated),
            "overall": {name: _metrics_to_dict(m) for name, m in self.overall.items()},
            "per_cwe": {
                cwe: {name: _metrics_to_dict(m) for name, m in inner.items()} for cwe, inner in self.per_cwe.items()
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
                    "test_name": row.case.test_name,
                    "cwe": row.case.cwe,
                    "category": row.case.category,
                    "real_vulnerability": row.case.real_vulnerability,
                    "target_violation_id": row.case.target_violation_id,
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


def _metrics_to_dict(m: MethodMetrics) -> dict[str, Any]:
    payload = {k: v for k, v in asdict(m).items() if k != "bootstrap"}
    payload["bootstrap"] = dict(m.bootstrap)
    return payload


def load_owasp_cases(
    csv_path: Path,
    java_root: Path,
    *,
    cwes: Iterable[str] | None = None,
    limit_per_cwe: int | None = None,
    seed: int = 0,
) -> list[OwaspCase]:
    """Load the OWASP expected-results CSV, restricted to CodeGraph CWEs."""
    target_cwes = frozenset(cwes) if cwes is not None else SUPPORTED_CWES
    if not target_cwes.issubset(SUPPORTED_CWES):
        unknown = target_cwes - SUPPORTED_CWES
        raise ValueError(f"Unsupported CWEs requested: {sorted(unknown)}")

    by_cwe: dict[str, list[OwaspCase]] = {cwe: [] for cwe in target_cwes}
    with csv_path.open("r", encoding="utf-8") as handle:
        reader = csv.reader(handle)
        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            if len(row) < 4:
                continue
            test_name, category, real_str, cwe = (
                row[0].strip(),
                row[1].strip(),
                row[2].strip().lower(),
                row[3].strip(),
            )
            if cwe not in target_cwes:
                continue
            java_path = java_root / f"{test_name}.java"
            if not java_path.is_file():
                continue
            by_cwe[cwe].append(
                OwaspCase(
                    test_name=test_name,
                    category=category,
                    real_vulnerability=real_str == "true",
                    cwe=cwe,
                    java_path=java_path,
                )
            )

    rng = random.Random(seed)
    flat: list[OwaspCase] = []
    for cwe in sorted(by_cwe.keys()):
        cases = by_cwe[cwe]
        rng.shuffle(cases)
        if limit_per_cwe is not None:
            cases = cases[:limit_per_cwe]
        flat.extend(cases)
    return flat
