from __future__ import annotations

import logging
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

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
)
from codegraph.ingestion.service import ingest
from codegraph.policy.integration import evaluate_policies


LOGGER = logging.getLogger(__name__)
ViolationIndex = Dict[str, List[Dict[str, Any]]]
ViolationKey = Tuple[str, str, str]


@dataclass(frozen=True)
class BenchmarkEvaluationContext:
    selection_cfg: Dict[str, Any]
    categories: List[CategorySpec]
    benchmark_root: Path
    truth_path: Path
    truth_schema: Dict[str, Any]
    truth_records: List[Any]
    selection: SelectionResult
    selected_category_ids: List[str]
    coverage_by_category: Dict[str, Dict[str, Any]]

    @property
    def categories_by_id(self) -> Dict[str, CategorySpec]:
        return {spec.id: spec for spec in self.categories}


@dataclass
class StagedBenchmarkWorkspace:
    work_root: Path
    java_root: Path
    staged_files: Dict[str, Path]


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
    testcase_ids: List[str],
    workdir: Optional[str],
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
    logger: Optional[logging.Logger] = None,
) -> Dict[str, Any]:
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


def group_violations_by_testcase(violations: List[Dict[str, Any]]) -> ViolationIndex:
    grouped: ViolationIndex = {}
    for violation in violations:
        testcase_id = extract_testcase_id(violation.get("target_method") or violation.get("file_path"))
        if not testcase_id:
            continue
        grouped.setdefault(testcase_id, []).append(violation)
    return grouped


def violation_identity_key(violation: Dict[str, Any]) -> ViolationKey:
    return (
        str(violation.get("violation_id")),
        str(violation.get("target_method")),
        str(violation.get("file_path")),
    )


def collect_category_violations(
    *,
    selected_category_ids: List[str],
    categories_by_id: Dict[str, CategorySpec],
    selection: SelectionResult,
    violations_by_testcase: ViolationIndex,
) -> Dict[str, List[Dict[str, Any]]]:
    """Collect TP-cohort violations: violations on positive (vulnerable) testcases.

    Used by run_explanation_eval and run_remediation_eval. Preserved as the
    canonical "true-positive" cohort accessor; do not change its semantics
    without auditing both callers.
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
    selected_category_ids: List[str],
    categories_by_id: Dict[str, CategorySpec],
    selection: SelectionResult,
    violations_by_testcase: ViolationIndex,
) -> Dict[str, List[Dict[str, Any]]]:
    """Collect FP-cohort violations: violations fired on benign (label=False)
    testcases. These are the false-positive predictions of the detection
    layer; the explanation eval (PR thesis/defensibility-pass, F01) uses
    them to measure citation grounding on the detector's mistakes.
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
    selected_category_ids: List[str],
    categories_by_id: Dict[str, CategorySpec],
    selection: SelectionResult,
    violations_by_testcase: ViolationIndex,
    positive_label: bool,
) -> Dict[str, List[Dict[str, Any]]]:
    category_violations_by_id: Dict[str, List[Dict[str, Any]]] = {}
    for category_id in selected_category_ids:
        spec = categories_by_id.get(category_id)
        if not spec:
            continue
        records = selection.selected_by_category.get(category_id, [])
        cohort_testcases = {rec.testcase_id for rec in records if bool(rec.label) is positive_label}
        seen_keys: set[ViolationKey] = set()
        category_violations: List[Dict[str, Any]] = []
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
