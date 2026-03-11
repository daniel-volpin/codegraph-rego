from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


HELPER_PATH = Path(__file__).resolve().parents[1] / "scripts" / "evaluation" / "reporting_helpers.py"
sys.path.insert(0, str(HELPER_PATH.parent))

SPEC = importlib.util.spec_from_file_location("reporting_helpers", HELPER_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def test_build_report_summarizes_default_style_runs(tmp_path: Path) -> None:
    outputs_root = tmp_path / "outputs"
    _write_json(
        outputs_root / "detection_calibration_path_precision_v4" / "metrics.json",
        {
            "generated_at": "2026-03-07T18:05:09+00:00",
            "selection": {"categories": ["a"], "max_cases_per_category": 60, "seed": 11},
            "coverage_by_category": {"a": {"sampled": True}},
            "metrics": {
                "overall": {
                    "tp": 12,
                    "fp": 3,
                    "fn": 5,
                    "tn": 20,
                    "precision": 0.8,
                    "recall": 0.7059,
                    "f1": 0.75,
                    "support": 40,
                },
                "a": {"tp": 12, "fp": 3, "fn": 5, "precision": 0.8, "recall": 0.7059, "f1": 0.75},
            },
            "violation_count": 17,
            "selected_testcases": [{"id": "tc-1"}],
        },
    )
    _write_json(
        outputs_root / "thesis_final_explanation_full" / "citation_metrics.json",
        {
            "generated_at": "2026-03-07T18:52:11+00:00",
            "selection": {"categories": ["a"], "max_cases_per_category": 60, "seed": 11},
            "coverage_by_category": {"a": {"sampled": True}},
            "metrics": {
                "overall": {
                    "count": 12,
                    "with_context": 10,
                    "without_context": 9,
                    "rate_with_context": 0.8333,
                    "rate_without_context": 0.75,
                },
                "a": {
                    "count": 12,
                    "with_context": 10,
                    "without_context": 9,
                    "rate_with_context": 0.8333,
                    "rate_without_context": 0.75,
                },
            },
            "sample_count": 12,
        },
    )
    _write_json(
        outputs_root / "repro_supported_medium_branch_benchmarktest01017_fix" / "remediation_metrics.json",
        {
            "generated_at": "2026-03-07T19:47:45+00:00",
            "selection": {"categories": ["a"], "max_cases_per_category": 60, "seed": 11},
            "coverage_by_category": {"a": {"sampled": True}},
            "attempted": 4,
            "fix_success": 2,
            "build_attempted": 4,
            "build_success": 4,
            "fix_success_rate": 0.5,
            "build_success_rate": 1.0,
            "results": [
                {
                    "status": "OK",
                    "policy_pass": True,
                    "patch_applied": True,
                    "build_pass": True,
                    "generation": {"decision": "replace_method", "raw_response_valid": True},
                },
                {
                    "status": "OK",
                    "policy_pass": True,
                    "patch_applied": True,
                    "build_pass": True,
                    "generation": {"decision": "replace_method", "raw_response_valid": True},
                },
                {
                    "status": "GENERATION_ERROR",
                    "policy_pass": False,
                    "patch_applied": False,
                    "build_pass": False,
                    "generation": {"decision": "replace_method", "raw_response_valid": False},
                },
                {
                    "status": "GENERATION_ERROR",
                    "policy_pass": False,
                    "patch_applied": False,
                    "build_pass": False,
                    "generation": {"decision": "replace_method", "raw_response_valid": False},
                },
            ],
        },
    )
    _write_json(
        outputs_root / "final_full_remediation_current_main" / "remediation_metrics.json",
        {
            "generated_at": "2026-03-07T23:43:44+00:00",
            "selection": {"categories": ["a"], "max_cases_per_category": 60, "seed": 11},
            "coverage_by_category": {"a": {"sampled": True}},
            "attempted": 4,
            "fix_success": 3,
            "structured_valid": 4,
            "replacement_applied": 4,
            "policy_pass_count": 3,
            "build_attempted": 4,
            "build_success": 3,
            "fix_success_rate": 0.75,
            "build_success_rate": 0.75,
            "results": [
                {
                    "status": "OK",
                    "policy_pass": True,
                    "patch_applied": True,
                    "build_pass": True,
                    "generation": {"decision": "apply_edits", "raw_response_valid": True},
                },
                {
                    "status": "OK",
                    "policy_pass": True,
                    "patch_applied": True,
                    "build_pass": True,
                    "generation": {"decision": "apply_edits", "raw_response_valid": True},
                },
                {
                    "status": "OK",
                    "policy_pass": True,
                    "patch_applied": True,
                    "build_pass": True,
                    "generation": {"decision": "apply_edits", "raw_response_valid": True},
                },
                {
                    "status": "BUILD_ERROR",
                    "policy_pass": False,
                    "patch_applied": True,
                    "build_pass": False,
                    "generation": {"decision": "apply_edits", "raw_response_valid": True},
                },
            ],
        },
    )
    _write_json(
        outputs_root / "span_edit_bounded_smoke_v2" / "remediation_metrics.json",
        {
            "generated_at": "2026-03-07T23:34:50+00:00",
            "selection": {"categories": ["a"], "max_cases_per_category": 3, "seed": 11},
            "coverage_by_category": {"a": {"sampled": True}},
            "attempted": 3,
            "fix_success": 3,
            "structured_valid": 3,
            "replacement_applied": 3,
            "policy_pass_count": 3,
            "build_attempted": 3,
            "build_success": 3,
            "fix_success_rate": 1.0,
            "build_success_rate": 1.0,
            "results": [
                {
                    "status": "OK",
                    "policy_pass": True,
                    "patch_applied": True,
                    "build_pass": True,
                    "generation": {"decision": "apply_edits", "raw_response_valid": True},
                },
                {
                    "status": "OK",
                    "policy_pass": True,
                    "patch_applied": True,
                    "build_pass": True,
                    "generation": {"decision": "apply_edits", "raw_response_valid": True},
                },
                {
                    "status": "OK",
                    "policy_pass": True,
                    "patch_applied": True,
                    "build_pass": True,
                    "generation": {"decision": "apply_edits", "raw_response_valid": True},
                },
            ],
        },
    )

    report = MODULE.build_report(outputs_root, list(MODULE.DEFAULT_RUN_SPECS))
    comparisons = {item["current_run_id"]: item for item in report["comparisons"]}

    assert report["runs"][0]["summary"]["f1"] == 0.75
    assert report["runs"][1]["summary"]["citation_rate_with_context"] == 0.8333
    assert comparisons["current_main_supported_regression"]["delta"]["fix_success_rate_points"] == 25.0
    assert comparisons["current_bounded_compile_backed"]["delta"]["build_success_rate_points"] == 0.0
    assert any("fully verified compile-backed fixes" in item["text"] for item in report["headlines"])
    assert report["case_studies"] == []


def test_remediation_summary_derives_counts_for_legacy_outputs(tmp_path: Path) -> None:
    outputs_root = tmp_path / "outputs"
    _write_json(
        outputs_root / "legacy" / "remediation_metrics.json",
        {
            "generated_at": "2026-03-07T19:47:45+00:00",
            "selection": {"categories": ["a"], "max_cases_per_category": 60, "seed": 11},
            "coverage_by_category": {"a": {"sampled": True}},
            "results": [
                {
                    "status": "OK",
                    "policy_pass": True,
                    "patch_applied": True,
                    "build_pass": None,
                    "generation": {"decision": "replace_method", "raw_response_valid": True},
                },
                {
                    "status": "GENERATION_ERROR",
                    "policy_pass": False,
                    "patch_applied": False,
                    "build_pass": None,
                    "generation": {"decision": "replace_method", "raw_response_valid": False},
                },
            ],
        },
    )

    spec = MODULE.RunSpec(
        run_id="legacy",
        stage="remediation",
        label="Legacy Remediation",
        path="legacy",
    )
    summary = MODULE.summarize_run(outputs_root, spec)

    assert summary["summary"]["attempted"] == 2
    assert summary["summary"]["structured_valid"] == 1
    assert summary["summary"]["replacement_applied"] == 1
    assert summary["summary"]["policy_pass_count"] == 1
    assert summary["summary"]["verification_mode"] == "policy_only"


def test_write_report_outputs_json_and_markdown(tmp_path: Path) -> None:
    report = {
        "generated_at": "2026-03-08T00:00:00+00:00",
        "outputs_root": "/tmp/outputs",
        "runs": [],
        "comparisons": [],
        "headlines": [],
    }

    report_json, report_md = MODULE.write_report(report, tmp_path / "reporting")

    assert report_json.read_text(encoding="utf-8").startswith("{")
    assert "# Benchmark Reporting Summary" in report_md.read_text(encoding="utf-8")
