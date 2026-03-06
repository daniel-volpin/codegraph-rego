import json
import tempfile
import unittest
from pathlib import Path

from codegraph.evaluation.explanation_runtime import ExplanationRuntime


class TestExplanationRuntime(unittest.TestCase):
    def test_runtime_writes_progress_partial_and_samples(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir) / "eval"
            runtime = ExplanationRuntime(
                output_dir=output_dir,
                benchmark_root=Path("/tmp/benchmark"),
                truth_path=Path("/tmp/benchmark/expectedresults-1.2.csv"),
                truth_schema={"format": "csv"},
                selection_cfg={"categories": ["hash-md5"]},
                coverage_by_category={"hash-md5": {"selected_cases": 2}},
                sample_per_category=1,
            )

            runtime.write_stage_progress("selection", "Subset selected", selected_testcases=2)
            progress_selection = json.loads((output_dir / "progress.json").read_text(encoding="utf-8"))
            self.assertEqual(progress_selection["stage"], "selection")
            self.assertEqual(progress_selection["selected_testcases"], 2)

            metrics = {"hash-md5": {"count": 0, "with_context": 0, "without_context": 0}}
            runtime.begin_explanations(total_target_violations=2, metrics=metrics)
            runtime.start_category("hash-md5", "Hash (CWE-328)", 2, metrics=metrics)
            runtime.record_violation_result(with_context_hit=True, without_context_hit=False, metrics=metrics)
            runtime.write_sample({"category": "Hash (CWE-328)", "violation_id": "iso27001_hash_md5"})

            progress_running = json.loads((output_dir / "progress.json").read_text(encoding="utf-8"))
            self.assertEqual(progress_running["status"], "running")
            self.assertEqual(progress_running["processed_violations"], 1)
            self.assertEqual(progress_running["total_violations"], 2)
            self.assertEqual(progress_running["sample_count"], 0)

            sample_lines = (output_dir / "explanation_samples.jsonl").read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(len(sample_lines), 1)

            runtime.finalize(status="completed", metrics=metrics)

            progress_completed = json.loads((output_dir / "progress.json").read_text(encoding="utf-8"))
            partial_completed = json.loads((output_dir / "partial_metrics.json").read_text(encoding="utf-8"))
            self.assertEqual(progress_completed["status"], "completed")
            self.assertEqual(progress_completed["stage"], "finalization")
            self.assertEqual(progress_completed["sample_count"], 1)
            self.assertEqual(partial_completed["status"], "completed")
            self.assertIn("overall_partial", partial_completed["metrics"])


if __name__ == "__main__":
    unittest.main()
