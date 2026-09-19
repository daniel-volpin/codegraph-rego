from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any


@dataclass
class CategorySpec:
    id: str
    label: str
    cwes: list[str]
    rego_rules: list[str]
    iso_controls: list[str] = field(default_factory=list)
    remediation_tier: str = "manual"
    framework_demo: bool = False


@dataclass
class GroundTruthRecord:
    testcase_id: str
    cwe: str
    label: bool
    category: str | None = None


@dataclass(frozen=True)
class CoverageStats:
    available_cases: int
    selected_cases: int
    sampled: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "available_cases": int(self.available_cases),
            "selected_cases": int(self.selected_cases),
            "sampled": bool(self.sampled),
        }


@dataclass
class SelectionResult:
    selected_by_category: dict[str, list[GroundTruthRecord]]
    selected_testcase_ids: list[str]
    coverage_by_category: dict[str, CoverageStats] = field(default_factory=dict)


class IncompleteCorpusError(RuntimeError):
    """Requested testcases are missing from the staged corpus (thesis mode)."""


def _normalize_cwe(value: str | None) -> str:
    if not value:
        return ""
    text = str(value).strip().upper()
    if text.isdigit():
        return f"CWE-{text}"
    if text.startswith("CWE-"):
        return text
    if "CWE" in text:
        parts = re.findall(r"CWE-?\d+", text)
        if parts:
            return parts[0].replace("CWE", "CWE-").replace("--", "-")
    return text


def _normalize_key(key: str) -> str:
    return key.strip().lstrip("#").strip().lower().replace(" ", "").replace("_", "").replace("-", "")


def _first_value(row: dict[str, Any], keys: Iterable[str]) -> str | None:
    for key in keys:
        if key in row and row[key] is not None:
            value = str(row[key]).strip()
            if value:
                return value
    return None


def _parse_truth(value: str | None) -> bool | None:
    if value is None:
        return None
    lowered = value.strip().lower()
    if lowered in {"true", "1", "yes", "y", "vulnerable"}:
        return True
    if lowered in {"false", "0", "no", "n", "clean"}:
        return False
    return None


def extract_testcase_id(value: str | None) -> str | None:
    if not value:
        return None
    match = re.search(r"(BenchmarkTest\d+)", value)
    return match.group(1) if match else None
