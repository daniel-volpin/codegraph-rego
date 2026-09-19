from __future__ import annotations

import csv
import logging
import os
import shutil
import xml.etree.ElementTree as ET
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from codegraph.evaluation.benchmark_models import (
    GroundTruthRecord,
    IncompleteCorpusError,
    _first_value,
    _normalize_cwe,
    _normalize_key,
    _parse_truth,
)

LOGGER = logging.getLogger(__name__)

_BENCHMARK_ROOT_VAR = "OWASP_BENCHMARK_ROOT"
_BENCHMARK_ROOT_MARKER = "expectedresults-1.2.csv"
_PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _discover_benchmark_root() -> Path | None:
    from codegraph.evaluation import benchmark as benchmark_mod
    project_root = getattr(benchmark_mod, "_PROJECT_ROOT", _PROJECT_ROOT)
    candidate = project_root / "BenchmarkJava"
    return candidate if (candidate / _BENCHMARK_ROOT_MARKER).is_file() else None


def ensure_benchmark_root_env() -> str | None:
    configured = os.environ.get(_BENCHMARK_ROOT_VAR)
    if configured:
        return configured
    discovered = _discover_benchmark_root()
    if discovered is None:
        return None
    LOGGER.info("Using discovered OWASP Benchmark checkout at %s", discovered)
    os.environ[_BENCHMARK_ROOT_VAR] = str(discovered)
    return str(discovered)


def _expand_env_path(value: str | None) -> str | None:
    if value is None:
        return None
    expanded = os.path.expandvars(value)
    if "$" in expanded:
        raise ValueError(
            f"Could not resolve {value!r}: {_BENCHMARK_ROOT_VAR} is not set and ./BenchmarkJava "
            f"does not hold the corpus. Run `make benchmark-corpus`, or export "
            f"{_BENCHMARK_ROOT_VAR}=/path/to/BenchmarkJava."
        )
    return expanded


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


def load_ground_truth(benchmark_root: Path, ground_truth_path: str | None) -> list[GroundTruthRecord]:
    truth_path = find_ground_truth_file(benchmark_root, ground_truth_path)
    if truth_path.suffix.lower() == ".csv":
        return _load_ground_truth_csv(truth_path)
    return _load_ground_truth_xml(truth_path)


def validate_staged_corpus(
    requested_ids: Iterable[str],
    staged: dict[str, Path],
    *,
    require_complete: bool,
) -> list[str]:
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
