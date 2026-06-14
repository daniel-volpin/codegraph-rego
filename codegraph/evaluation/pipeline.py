from __future__ import annotations

import logging
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from codegraph.db import get_neo4j_driver
from codegraph.evaluation.benchmark import (
    CategorySpec,
    SelectionResult,
    coverage_report,
    extract_testcase_id,
    find_ground_truth_file,
    inspect_ground_truth_schema,
    load_ground_truth,
    load_mapping_config,
    load_selection_config,
    select_testcases,
    stage_benchmark_subset,
    validate_staged_corpus,
)
from codegraph.ingestion.service import ingest
from codegraph.policy.integration import evaluate_policies

LOGGER = logging.getLogger(__name__)
ViolationIndex = dict[str, list[dict[str, Any]]]
ViolationKey = tuple[str, str, str]


@dataclass(frozen=True)
class BenchmarkEvaluationContext:
    selection_cfg: dict[str, Any]
    categories: list[CategorySpec]
    benchmark_root: Path
    truth_path: Path
    truth_schema: dict[str, Any]
    truth_records: list[Any]
    selection: SelectionResult
    selected_category_ids: list[str]
    coverage_by_category: dict[str, dict[str, Any]]

    @property
    def categories_by_id(self) -> dict[str, CategorySpec]:
        return {spec.id: spec for spec in self.categories}


@dataclass
class StagedBenchmarkWorkspace:
    work_root: Path
    java_root: Path
    staged_files: dict[str, Path]


def clear_graph() -> None:
    driver = get_neo4j_driver()
    try:
        with driver.session() as session:
            session.run("MATCH (n) DETACH DELETE n").consume()
    finally:
        driver.close()


def load_benchmark_evaluation_context(config_path: Path, mapping_path: Path) -> BenchmarkEvaluationContext:
    selection_cfg = load_selection_config(config_path)
    categories = load_mapping_config(mapping_path)
    benchmark_root = Path(selection_cfg["benchmark_root"])
    truth_path = find_ground_truth_file(benchmark_root, selection_cfg.get("ground_truth_path"))
    truth_schema = inspect_ground_truth_schema(truth_path)
    truth_records = load_ground_truth(benchmark_root, truth_path.as_posix())
    selection = select_testcases(truth_records, categories, selection_cfg)
    selected_category_ids = selection_cfg.get("categories") or [spec.id for spec in categories]
    return BenchmarkEvaluationContext(
        selection_cfg=selection_cfg,
        categories=categories,
        benchmark_root=benchmark_root,
        truth_path=truth_path,
        truth_schema=truth_schema,
        truth_records=truth_records,
        selection=selection,
        selected_category_ids=selected_category_ids,
        coverage_by_category=coverage_report(selection, selected_category_ids),
    )


@contextmanager
def staged_benchmark_workspace(
    *,
    benchmark_root: Path,
    java_relative_root: str,
    testcase_ids: list[str],
    workdir: str | None,
    require_complete: bool = False,
) -> Iterator[StagedBenchmarkWorkspace]:
    temp_context: tempfile.TemporaryDirectory[str] | None = None
    if workdir:
        work_root = Path(workdir)
        work_root.mkdir(parents=True, exist_ok=True)
    else:
        temp_context = tempfile.TemporaryDirectory()
        work_root = Path(temp_context.name)

    try:
        staged_files = stage_benchmark_subset(
            benchmark_root,
            java_relative_root,
            testcase_ids,
            work_root,
        )
        # Thesis/canonical mode: refuse to proceed on a partial checkout so a
        # smaller-than-declared population can never be reported as a thesis metric.
        validate_staged_corpus(testcase_ids, staged_files, require_complete=require_complete)
        yield StagedBenchmarkWorkspace(
            work_root=work_root,
            java_root=work_root / java_relative_root,
            staged_files=staged_files,
        )
    finally:
        if temp_context is not None:
            temp_context.cleanup()


def ingest_and_evaluate_subset(
    *,
    java_root: Path,
    reset_neo4j: bool,
    logger: logging.Logger | None = None,
) -> dict[str, Any]:
    import shutil

    active_logger = logger or LOGGER

    if not shutil.which("opa"):
        err_msg = "OPA CLI not found on PATH. Please install OPA or run `make install`."
        active_logger.error(err_msg)
        return {"error": err_msg}

    if reset_neo4j:
        clear_graph()

    active_logger.info("Ingesting OWASP Benchmark subset from %s", java_root)
    ingest(java_root.as_posix())

    active_logger.info("Evaluating policies via OPA/Rego")
    return evaluate_policies()


def group_violations_by_testcase(violations: list[dict[str, Any]]) -> ViolationIndex:
    grouped: ViolationIndex = {}
    for violation in violations:
        testcase_id = extract_testcase_id(violation.get("target_method") or violation.get("file_path"))
        if not testcase_id:
            continue
        grouped.setdefault(testcase_id, []).append(violation)
    return grouped


def violation_identity_key(violation: dict[str, Any]) -> ViolationKey:
    return (
        str(violation.get("violation_id")),
        str(violation.get("target_method")),
        str(violation.get("file_path")),
    )


def collect_category_violations(
    *,
    selected_category_ids: list[str],
    categories_by_id: dict[str, CategorySpec],
    selection: SelectionResult,
    violations_by_testcase: ViolationIndex,
) -> dict[str, list[dict[str, Any]]]:
    """Collect TP-cohort violations: rules fired on positive testcases.

    Both ``run_explanation_eval`` and ``run_remediation_eval`` depend on
    this exact semantics; audit both callers before changing it.
    """
    return _collect_category_violations_by_label(
        selected_category_ids=selected_category_ids,
        categories_by_id=categories_by_id,
        selection=selection,
        violations_by_testcase=violations_by_testcase,
        positive_label=True,
    )


def collect_category_false_positive_violations(
    *,
    selected_category_ids: list[str],
    categories_by_id: dict[str, CategorySpec],
    selection: SelectionResult,
    violations_by_testcase: ViolationIndex,
) -> dict[str, list[dict[str, Any]]]:
    """Collect FP-cohort violations: rules fired on benign (label=False)
    testcases. Used by the explanation eval to measure citation grounding
    on the detector's false positives.
    """
    return _collect_category_violations_by_label(
        selected_category_ids=selected_category_ids,
        categories_by_id=categories_by_id,
        selection=selection,
        violations_by_testcase=violations_by_testcase,
        positive_label=False,
    )


def _collect_category_violations_by_label(
    *,
    selected_category_ids: list[str],
    categories_by_id: dict[str, CategorySpec],
    selection: SelectionResult,
    violations_by_testcase: ViolationIndex,
    positive_label: bool,
) -> dict[str, list[dict[str, Any]]]:
    category_violations_by_id: dict[str, list[dict[str, Any]]] = {}
    for category_id in selected_category_ids:
        spec = categories_by_id.get(category_id)
        if not spec:
            continue
        records = selection.selected_by_category.get(category_id, [])
        cohort_testcases = {rec.testcase_id for rec in records if bool(rec.label) is positive_label}
        seen_keys: set[ViolationKey] = set()
        category_violations: list[dict[str, Any]] = []
        for testcase_id in cohort_testcases:
            for violation in violations_by_testcase.get(testcase_id, []):
                if violation.get("violation_id") not in spec.rego_rules:
                    continue
                key = violation_identity_key(violation)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                category_violations.append(violation)
        category_violations_by_id[category_id] = category_violations
    return category_violations_by_id
