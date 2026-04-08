import json
import tempfile
import unittest
from pathlib import Path

from codegraph.evaluation.remediation_runtime import (
    RemediationRuntime,
    build_metrics_payload,
    build_remediation_result,
    write_final_artifacts,
)


class TestRemediationRuntime(unittest.TestCase):
    def test_runtime_writes_incremental_progress_and_case_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir) / "eval"
            runtime = RemediationRuntime(
                output_dir=output_dir,
                benchmark_root=Path("/tmp/benchmark"),
                truth_path=Path("/tmp/benchmark/expectedresults-1.2.csv"),
                truth_schema={"format": "csv"},
                selection_cfg={"categories": ["hash-md5"]},
                coverage_by_category={"hash-md5": {"selected_cases": 2}},
                mode="dry_run",
                max_attempts=2,
            )

            runtime.write_stage_progress(
                "selection",
                "Loaded remediation context",
                selected_testcases=2,
            )
            progress_selection = json.loads((output_dir / "progress.json").read_text(encoding="utf-8"))
            self.assertEqual(progress_selection["stage"], "selection")
            self.assertEqual(progress_selection["selected_testcases"], 2)
            self.assertEqual(progress_selection["mode"], "dry_run")
            self.assertEqual(progress_selection["max_attempts"], 2)

            runtime.begin(total_cases=2)

            violation_ok = {
                "violation_id": "ISO-A.10-WEAK-HASH",
                "target_method": "org.owasp.benchmark.testcode.BenchmarkTest00001.doPost()",
                "file_path": "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00001.java",
                "category": "Hash (CWE-328)",
                "evidence": {
                    "file_path": ("src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00001.java"),
                },
            }
            case_id_ok, case_dir_ok = runtime.prepare_case(violation_ok)
            apply_result_ok = {
                "status": "OK",
                "error": None,
                "updated_source_code": ('MessageDigest digest = MessageDigest.getInstance("SHA-256");'),
                "confidence": {
                    "score": 0.91,
                    "band": "apply",
                },
                "verification": {"target_rule_status": "PASS", "overall_status": "PASS"},
                "compilation": {"attempted": True, "success": True},
                "diff": "--- before\n+++ after\n@@\n-md5\n+sha256\n",
                "generation": {"raw_response_valid": True},
                "errors": [],
                "attempt_count": 1,
                "raw_capture_files": [],
            }
            result_ok = build_remediation_result(
                violation=violation_ok,
                apply_result=apply_result_ok,
                case_id=case_id_ok,
            )
            runtime.record_case(apply_result=apply_result_ok, result=result_ok)

            progress_running = json.loads((output_dir / "progress.json").read_text(encoding="utf-8"))
            self.assertEqual(progress_running["status"], "running")
            self.assertEqual(progress_running["processed_cases"], 1)
            self.assertEqual(progress_running["total_cases"], 2)
            self.assertEqual(progress_running["attempted"], 1)
            self.assertEqual(progress_running["structured_valid"], 1)
            self.assertEqual(progress_running["replacement_applied"], 1)
            self.assertEqual(progress_running["build_attempted"], 1)
            self.assertEqual(progress_running["build_success"], 1)
            self.assertEqual(progress_running["policy_fixed"], 1)
            self.assertEqual(progress_running["final_status_counts"]["OK"], 1)

            self.assertTrue((case_dir_ok / "violation.json").exists())
            self.assertTrue((case_dir_ok / "result.json").exists())
            self.assertTrue((case_dir_ok / "apply_result.json").exists())
            self.assertTrue((case_dir_ok / "diff.patch").exists())
            self.assertTrue((case_dir_ok / "verification.json").exists())
            self.assertTrue((case_dir_ok / "compilation.json").exists())
            self.assertTrue((case_dir_ok / "generation.json").exists())

            violation_no_fix = {
                "violation_id": "ISO-A.10-WEAK-CRYPTO",
                "target_method": "org.owasp.benchmark.testcode.BenchmarkTest00002.doPost()",
                "file_path": "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00002.java",
                "category": "Crypto (CWE-327)",
                "evidence": {
                    "file_path": ("src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00002.java"),
                },
            }
            case_id_no_fix, _ = runtime.prepare_case(violation_no_fix)
            apply_result_no_fix = {
                "status": "NO_FIX",
                "error": "NO_FIX: broader protocol context required",
                "confidence": {
                    "score": 0.34,
                    "band": "abstain",
                },
                "verification": {},
                "compilation": {
                    "attempted": False,
                    "success": False,
                    "skipped_reason": "No build system detected",
                },
                "generation": {"raw_response_valid": True},
                "errors": ["broader protocol context required"],
                "attempt_count": 1,
                "raw_capture_files": [],
            }
            result_no_fix = build_remediation_result(
                violation=violation_no_fix,
                apply_result=apply_result_no_fix,
                case_id=case_id_no_fix,
            )
            runtime.record_case(apply_result=apply_result_no_fix, result=result_no_fix)

            progress_two = json.loads((output_dir / "progress.json").read_text(encoding="utf-8"))
            self.assertEqual(progress_two["attempted"], 2)
            self.assertEqual(progress_two["structured_valid"], 2)
            self.assertEqual(progress_two["replacement_applied"], 1)
            self.assertEqual(progress_two["build_attempted"], 1)
            self.assertEqual(progress_two["build_success"], 1)
            self.assertEqual(progress_two["policy_fixed"], 1)
            self.assertEqual(progress_two["final_status_counts"]["OK"], 1)
            self.assertEqual(progress_two["final_status_counts"]["NO_FIX"], 1)

            result_lines = (output_dir / "results.jsonl").read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(result_lines), 2)
            self.assertEqual(json.loads(result_lines[0])["case_id"], case_id_ok)
            self.assertEqual(json.loads(result_lines[1])["case_id"], case_id_no_fix)

            metrics = build_metrics_payload(
                benchmark_root=Path("/tmp/benchmark"),
                truth_path=Path("/tmp/benchmark/expectedresults-1.2.csv"),
                truth_schema={"format": "csv"},
                selection_cfg={"categories": ["hash-md5"]},
                coverage_by_category={"hash-md5": {"selected_cases": 2}},
                mode="dry_run",
                max_attempts=2,
                legacy_build_command_arg=None,
                results=[result_ok, result_no_fix],
            )
            write_final_artifacts(output_dir, metrics, table_format="md")
            runtime.finalize(status="completed")

            progress_completed = json.loads((output_dir / "progress.json").read_text(encoding="utf-8"))
            self.assertEqual(progress_completed["status"], "completed")
            self.assertEqual(progress_completed["stage"], "finalization")

            remediation_metrics = json.loads((output_dir / "remediation_metrics.json").read_text(encoding="utf-8"))
            self.assertEqual(remediation_metrics["attempted"], 2)
            self.assertEqual(remediation_metrics["final_status_counts"]["OK"], 1)
            self.assertEqual(remediation_metrics["final_status_counts"]["NO_FIX"], 1)
            self.assertIn("confidence_calibration", remediation_metrics)
            self.assertIsNotNone(remediation_metrics["confidence_calibration"])

            self.assertTrue((output_dir / "remediation_metrics.csv").exists())
            self.assertTrue((output_dir / "confidence_calibration.json").exists())
            self.assertTrue((output_dir / "table.md").exists())

            summary = (output_dir / "summary.md").read_text(encoding="utf-8")
            self.assertIn("- Attempted: `2` / `2`", summary)
            self.assertIn("- `OK`: `1`", summary)
            self.assertIn("- `NO_FIX`: `1`", summary)
            self.assertIn("## Confidence Calibration", summary)
            self.assertIn(case_id_no_fix, summary)


if __name__ == "__main__":
    unittest.main()
