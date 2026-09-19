from __future__ import annotations

import json
import logging
import random
from pathlib import Path
from typing import Any

from codegraph.evaluation.benchmark_models import (
    CategorySpec,
    CoverageStats,
    GroundTruthRecord,
    IncompleteCorpusError,
    SelectionResult,
    _first_value,
    _normalize_cwe,
    _normalize_key,
    _parse_truth,
    extract_testcase_id,
)
from codegraph.evaluation.benchmark_staging import (
    _BENCHMARK_ROOT_VAR,
    _discover_benchmark_root,
    _expand_env_path,
    _load_ground_truth_csv,
    _load_ground_truth_xml,
    ensure_benchmark_root_env,
    find_ground_truth_file,
    inspect_ground_truth_schema,
    load_ground_truth,
    stage_benchmark_subset,
    validate_staged_corpus,
)

LOGGER = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parents[2]

__all__ = [
    "CategorySpec",
    "CoverageStats",
    "GroundTruthRecord",
    "IncompleteCorpusError",
    "SelectionResult",
    "_BENCHMARK_ROOT_VAR",
    "_PROJECT_ROOT",
    "_discover_benchmark_root",
    "_expand_env_path",
    "_first_value",
    "_load_ground_truth_csv",
    "_load_ground_truth_xml",
    "_normalize_cwe",
    "_normalize_key",
    "_parse_truth",
    "coverage_report",
    "ensure_benchmark_root_env",
    "extract_testcase_id",
    "find_ground_truth_file",
    "inspect_ground_truth_schema",
    "load_ground_truth",
    "load_mapping_config",
    "load_selection_config",
    "select_testcases",
    "stage_benchmark_subset",
    "validate_staged_corpus",
]


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
    ensure_benchmark_root_env()
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
        "max_cases_per_category": max_cases,
        "seed": payload.get("seed", 7),
        "debug_fn_analysis": bool(payload.get("debug_fn_analysis", False)),
        "build_command": payload.get("build_command"),
    }


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
    report: dict[str, dict[str, Any]] = {}
    for category_id in selected_category_ids:
        stats = selection.coverage_by_category.get(category_id)
        if stats is None:
            continue
        report[category_id] = stats.as_dict()
    return report
