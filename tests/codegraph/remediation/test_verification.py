import os
import unittest
from unittest.mock import patch

from tests.codegraph.remediation._test_helpers import RemediationTestBase


class VerificationTests(RemediationTestBase):
    def test_unified_diff(self):
        diff = self.service._unified_diff("a\nb", "a\nc", label="method")
        self.assertIn("-b", diff)
        self.assertIn("+c", diff)

    def test_verification_summary_passes_when_target_rule_removed_and_only_baseline_manual_findings_remain(self):
        summary = self.service._build_verification_summary(
            "ISO-A.10-WEAK-RANDOM",
            baseline=[
                {"violation_id": "ISO-A.10-WEAK-RANDOM", "target_method": "m", "file_path": "f"},
                {"violation_id": "ISO-A.8-CMD-INJECTION", "target_method": "m", "file_path": "f"},
            ],
            after=[
                {"violation_id": "ISO-A.8-CMD-INJECTION", "target_method": "m", "file_path": "f"},
            ],
        )

        self.assertEqual(summary["target_rule_status"], "PASS")
        self.assertEqual(summary["overall_status"], "PASS")
        self.assertEqual([v["violation_id"] for v in summary["remaining_violations"]], ["ISO-A.8-CMD-INJECTION"])
        self.assertEqual(summary["new_violations"], [])

    def test_verification_summary_fails_when_new_violation_is_introduced(self):
        summary = self.service._build_verification_summary(
            "ISO-A.10-WEAK-RANDOM",
            baseline=[
                {"violation_id": "ISO-A.10-WEAK-RANDOM", "target_method": "m", "file_path": "f"},
            ],
            after=[
                {"violation_id": "ISO-A.8-CMD-INJECTION", "target_method": "m", "file_path": "f"},
            ],
        )

        self.assertEqual(summary["target_rule_status"], "PASS")
        self.assertEqual(summary["overall_status"], "FAIL")
        self.assertEqual([v["violation_id"] for v in summary["new_violations"]], ["ISO-A.8-CMD-INJECTION"])

    @patch("codegraph.remediation.service.gather_violation_context", return_value={"rule_id": "ISO-A.10-WEAK-HASH"})
    @patch("codegraph.remediation.service.evaluate_policies", return_value={"violations": []})
    def test_get_violation_context_scopes_policy_evaluation_to_upload_dir_by_default(
        self,
        mock_evaluate_policies,
        mock_gather_context,
    ):
        remediation = self.service.RemediationService(llm_client=lambda _messages, **_: "")

        result = remediation.get_violation_context("ISO-A.10-WEAK-HASH")

        self.assertEqual(result, {"rule_id": "ISO-A.10-WEAK-HASH"})
        evaluate_fn = mock_gather_context.call_args.kwargs["evaluate_policies_fn"]
        evaluate_fn()
        from codegraph.config import settings

        self.assertEqual(
            mock_evaluate_policies.call_args.kwargs["workspace_root"],
            os.path.abspath(settings.upload_dir),
        )

    @patch("codegraph.remediation.service.gather_violation_context", return_value={"rule_id": "ISO-A.10-WEAK-HASH"})
    @patch("codegraph.remediation.service.evaluate_policies", return_value={"violations": []})
    def test_get_violation_context_scopes_policy_evaluation_to_explicit_file_path(
        self,
        mock_evaluate_policies,
        mock_gather_context,
    ):
        remediation = self.service.RemediationService(llm_client=lambda _messages, **_: "")
        benchmark_file = "/tmp/benchmark/src/main/java/org/example/BenchmarkTest00001.java"

        result = remediation.get_violation_context("ISO-A.10-WEAK-HASH", file_path=benchmark_file)

        self.assertEqual(result, {"rule_id": "ISO-A.10-WEAK-HASH"})
        evaluate_fn = mock_gather_context.call_args.kwargs["evaluate_policies_fn"]
        evaluate_fn()
        self.assertEqual(
            mock_evaluate_policies.call_args.kwargs["workspace_root"],
            os.path.abspath(benchmark_file),
        )

    def test_get_violation_context_re_evaluates_for_distinct_workspace_roots(self):
        from codegraph.remediation.context import clear_policy_evaluation_cache

        clear_policy_evaluation_cache()
        remediation = self.service.RemediationService(llm_client=lambda _messages, **_: "")
        first_file = "/tmp/benchmark-a/src/main/java/org/example/BenchmarkTest00001.java"
        second_file = "/tmp/benchmark-b/src/main/java/org/example/BenchmarkTest00002.java"

        first_result = {
            "violations": [
                {
                    "violation_id": "ISO-A.10-WEAK-HASH",
                    "target_method": "org.example.BenchmarkTest00001.doPost()",
                    "file_path": os.path.abspath(first_file),
                    "evidence": {},
                }
            ]
        }
        second_result = {
            "violations": [
                {
                    "violation_id": "ISO-A.10-WEAK-HASH",
                    "target_method": "org.example.BenchmarkTest00002.doPost()",
                    "file_path": os.path.abspath(second_file),
                    "evidence": {},
                }
            ]
        }

        with (
            patch.object(self.service, "evaluate_policies", side_effect=[first_result, second_result]) as mock_evaluate,
            patch.object(self.service, "load_policy_catalog", return_value={}),
            patch.object(self.service, "resolve_file_path", return_value=None),
            patch.object(self.service, "build_remediation_plan", return_value={}),
            patch.object(self.service, "PolicyEvaluator") as mock_evaluator,
        ):
            mock_evaluator.return_value.evaluate.return_value = {"violations": []}

            first_context = remediation.get_violation_context("ISO-A.10-WEAK-HASH", file_path=first_file)
            second_context = remediation.get_violation_context("ISO-A.10-WEAK-HASH", file_path=second_file)

        clear_policy_evaluation_cache()

        self.assertEqual(mock_evaluate.call_count, 2)
        self.assertEqual(first_context["file_path"], os.path.abspath(first_file))
        self.assertEqual(second_context["file_path"], os.path.abspath(second_file))
        self.assertEqual(
            mock_evaluate.call_args_list[0].kwargs["workspace_root"],
            os.path.abspath(first_file),
        )
        self.assertEqual(
            mock_evaluate.call_args_list[1].kwargs["workspace_root"],
            os.path.abspath(second_file),
        )


if __name__ == "__main__":
    unittest.main()
