from __future__ import annotations

import csv
import json
import logging
import os
import random
import re
import shutil
import xml.etree.ElementTree as ET
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

LOGGER = logging.getLogger(__name__)


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


def _expand_env_path(value: str | None) -> str | None:
    if value is None:
        return None
    return os.path.expandvars(value)


def load_mapping_config(path: Path) -> list[CategorySpec]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    categories = payload.get("categories") if isinstance(payload, dict) else payload
    if not isinstance(categories, list):
        raise ValueError("Mapping file must include a 'categories' array.")
    specs: list[CategorySpec] = []
    for entry in categories:
        if not isinstance(entry, dict):
            continue
        specs.append(
            CategorySpec(
                id=str(entry.get("category_id") or entry.get("id") or entry.get("name")),
                label=str(entry.get("label") or entry.get("name") or entry.get("category_id") or entry.get("id")),
                cwes=[_normalize_cwe(cwe) for cwe in entry.get("cwes", []) if cwe],
                rego_rules=[
                    str(rule) for rule in (entry.get("rego_rule_ids") or entry.get("rego_rules") or []) if rule
                ],
                iso_controls=[
                    str(ctrl) for ctrl in (entry.get("control_ids") or entry.get("iso_controls") or []) if ctrl
                ],
                remediation_tier=str(entry.get("remediation_tier") or "manual"),
                framework_demo=bool(entry.get("framework_demo", False)),
            )
        )
    return specs


def load_selection_config(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict) or "benchmark_root" not in payload:
        raise ValueError("Selection config must include 'benchmark_root'.")
    raw_max_cases = payload.get("max_cases_per_category")
    max_cases: int | None = None
    if isinstance(raw_max_cases, int):
        max_cases = raw_max_cases if raw_max_cases > 0 else None
    elif isinstance(raw_max_cases, str) and raw_max_cases.strip().isdigit():
        parsed = int(raw_max_cases.strip())
        max_cases = parsed if parsed > 0 else None
    return {
        "benchmark_root": _expand_env_path(str(payload["benchmark_root"])),
        "java_relative_root": payload.get("java_relative_root", "src/main/java"),
        "ground_truth_path": _expand_env_path(payload.get("ground_truth_path")),
        "categories": payload.get("categories") or [],
        "testcase_ids": payload.get("testcase_ids") or [],
        # Missing/null/0 means "no sampling limit".
        "max_cases_per_category": max_cases,
        "seed": payload.get("seed", 7),
        "debug_fn_analysis": bool(payload.get("debug_fn_analysis", False)),
        "build_command": payload.get("build_command"),
    }


def find_ground_truth_file(benchmark_root: Path, override: str | None) -> Path:
    if override:
        path = Path(override)
        if not path.is_file():
            raise FileNotFoundError(f"Ground truth file not found: {override}")
        return path
    candidates = [
        "benchmarkdata.csv",
        "benchmarkdata.xml",
        "BenchmarkData.xml",
        "Benchmark.xml",
    ]
    for name in candidates:
        for candidate in benchmark_root.rglob(name):
            return candidate
    for candidate in benchmark_root.rglob("expectedresults*.csv"):
        return candidate
    raise FileNotFoundError("Could not locate benchmark ground truth (benchmarkdata.csv/xml or expectedresults*.csv).")


def inspect_ground_truth_schema(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"Ground truth file not found: {path}")
    if path.suffix.lower() == ".csv":
        with path.open("r", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            return {
                "format": "csv",
                "fieldnames": reader.fieldnames or [],
                "normalized_fieldnames": [_normalize_key(name) for name in (reader.fieldnames or [])],
            }
    tree = ET.parse(path)
    root = tree.getroot()
    attributes = []
    for elem in root.iter():
        if elem.tag.lower().endswith("testcase"):
            attributes = list(elem.attrib.keys())
            break
    return {
        "format": "xml",
        "root_tag": root.tag,
        "testcase_attributes": attributes,
    }


def load_ground_truth(benchmark_root: Path, ground_truth_path: str | None) -> list[GroundTruthRecord]:
    truth_path = find_ground_truth_file(benchmark_root, ground_truth_path)
    if truth_path.suffix.lower() == ".csv":
        return _load_ground_truth_csv(truth_path)
    return _load_ground_truth_xml(truth_path)


def _load_ground_truth_csv(path: Path) -> list[GroundTruthRecord]:
    records: list[GroundTruthRecord] = []
    with path.open("r", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            normalized = {_normalize_key(key): value for key, value in row.items()}
            testcase_id = _first_value(
                normalized,
                ["testcase", "testcaseid", "testname", "testcasename", "name"],
            )
            cwe = _first_value(normalized, ["cwe", "cweid"])
            truth_raw = _first_value(
                normalized,
                ["truefalse", "realvulnerability", "vulnerable", "isvulnerable"],
            )
            label = _parse_truth(truth_raw)
            if not testcase_id or label is None:
                continue
            records.append(
                GroundTruthRecord(
                    testcase_id=testcase_id,
                    cwe=_normalize_cwe(cwe),
                    label=label,
                    category=_first_value(normalized, ["category"]),
                )
            )
    return records


def _load_ground_truth_xml(path: Path) -> list[GroundTruthRecord]:
    records: list[GroundTruthRecord] = []
    tree = ET.parse(path)
    root = tree.getroot()
    for elem in root.iter():
        if not elem.tag.lower().endswith("testcase"):
            continue
        testcase_id = elem.attrib.get("name") or elem.attrib.get("testcase") or elem.attrib.get("id")
        truth_raw = elem.attrib.get("truefalse") or elem.attrib.get("vulnerable")
        label = _parse_truth(truth_raw)
        if not testcase_id or label is None:
            continue
        records.append(
            GroundTruthRecord(
                testcase_id=testcase_id,
                cwe=_normalize_cwe(elem.attrib.get("cwe")),
                label=label,
                category=elem.attrib.get("category"),
            )
        )
    return records


@dataclass
class SelectionResult:
    selected_by_category: dict[str, list[GroundTruthRecord]]
    selected_testcase_ids: list[str]
    coverage_by_category: dict[str, CoverageStats] = field(default_factory=dict)


def select_testcases(
    records: list[GroundTruthRecord],
    categories: list[CategorySpec],
    selection: dict[str, Any],
) -> SelectionResult:
    selected_ids = selection.get("categories") or [spec.id for spec in categories]
    filter_set = set(selection.get("testcase_ids") or [])
    max_cases = selection.get("max_cases_per_category")
    seed = selection.get("seed", 7)
    categories_by_id = {spec.id: spec for spec in categories}
    selected_by_category: dict[str, list[GroundTruthRecord]] = {}
    selected_testcases: list[str] = []
    coverage_by_category: dict[str, CoverageStats] = {}

    for idx, category_id in enumerate(selected_ids):
        spec = categories_by_id.get(category_id)
        if not spec:
            LOGGER.warning("Unknown category id %s in selection config.", category_id)
            continue
        cwe_set = {_normalize_cwe(cwe) for cwe in spec.cwes if cwe}
        candidates = [rec for rec in records if _normalize_cwe(rec.cwe) in cwe_set]
        if filter_set:
            candidates = [rec for rec in candidates if rec.testcase_id in filter_set]
        available_cases = len(candidates)
        sampled = False
        if isinstance(max_cases, int) and max_cases > 0 and len(candidates) > max_cases:
            rng = random.Random(seed + idx)
            candidates = rng.sample(candidates, k=max_cases)
            sampled = True
        selected_by_category[category_id] = candidates
        selected_testcases.extend([rec.testcase_id for rec in candidates])
        coverage_by_category[category_id] = CoverageStats(
            available_cases=available_cases,
            selected_cases=len(candidates),
            sampled=sampled,
        )

    unique_testcases = sorted(set(selected_testcases))
    return SelectionResult(
        selected_by_category=selected_by_category,
        selected_testcase_ids=unique_testcases,
        coverage_by_category=coverage_by_category,
    )


def coverage_report(selection: SelectionResult, selected_category_ids: list[str]) -> dict[str, dict[str, Any]]:
    """Return JSON-serializable coverage stats for the selected category ids."""
    report: dict[str, dict[str, Any]] = {}
    for category_id in selected_category_ids:
        stats = selection.coverage_by_category.get(category_id)
        if stats is None:
            continue
        report[category_id] = stats.as_dict()
    return report


class IncompleteCorpusError(RuntimeError):
    """Requested testcases are missing from the staged corpus (thesis mode)."""


def validate_staged_corpus(
    requested_ids: Iterable[str],
    staged: dict[str, Path],
    *,
    require_complete: bool,
) -> list[str]:
    """Return missing testcase IDs; raise ``IncompleteCorpusError`` when complete is required."""
    requested = list(requested_ids)
    missing = sorted(set(requested) - set(staged))
    if require_complete and missing:
        raise IncompleteCorpusError(
            f"Incomplete benchmark corpus: {len(missing)} of {len(requested)} requested "
            f"testcases are not staged (e.g. {', '.join(missing[:10])}). Refusing to report "
            "thesis metrics from a partial checkout. Verify OWASP_BENCHMARK_ROOT, or rerun "
            "without --require-complete-corpus for a non-thesis exploratory run."
        )
    return missing


def stage_benchmark_subset(
    benchmark_root: Path,
    java_relative_root: str,
    testcase_ids: Iterable[str],
    dest_root: Path,
) -> dict[str, Path]:
    source_root = benchmark_root / java_relative_root
    dest_java_root = dest_root / java_relative_root
    dest_java_root.mkdir(parents=True, exist_ok=True)
    staged: dict[str, Path] = {}
    missing: list[str] = []

    scaffold_entries = [
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "settings.gradle",
        "settings.gradle.kts",
        "mvnw",
        "mvnw.cmd",
        "gradlew",
        "gradlew.bat",
        ".mvn",
        "gradle",
        "DevStyleHtml.prefs",
        "DevStyleXml.prefs",
        "src/main/resources",
        "src/main/java/org/owasp/benchmark/helpers",
        "src/main/java/org/owasp/benchmark/service",
    ]

    for relative in scaffold_entries:
        src = benchmark_root / relative
        if not src.exists():
            continue
        dest = dest_root / relative
        if src.is_dir():
            shutil.copytree(src, dest, dirs_exist_ok=True)
        else:
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest)

    for testcase_id in testcase_ids:
        matches = list(source_root.rglob(f"{testcase_id}.java"))
        if not matches:
            missing.append(testcase_id)
            continue
        src_path = matches[0]
        rel_path = src_path.relative_to(source_root)
        dest_path = dest_java_root / rel_path
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src_path, dest_path)
        staged[testcase_id] = dest_path

    if missing:
        LOGGER.warning("Missing %d testcase files: %s", len(missing), ", ".join(missing[:5]))
    return staged


def extract_testcase_id(value: str | None) -> str | None:
    if not value:
        return None
    match = re.search(r"(BenchmarkTest\d+)", value)
    return match.group(1) if match else None
