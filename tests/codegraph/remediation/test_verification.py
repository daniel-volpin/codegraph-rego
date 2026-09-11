import os
import shutil
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from codegraph.ingestion.snapshots import create_source_snapshot_from_bytes, sha256_hex
from tests.codegraph.remediation._test_helpers import RemediationTestBase

FIRST_METHOD_KEY = "workspace@revision:src/main/java/org/example/BenchmarkTest00001.java#file:src/main/java/org/example/BenchmarkTest00001.java#type:BenchmarkTest00001#method:doPost/0/#range:0-1"
SECOND_METHOD_KEY = "workspace@revision:src/main/java/org/example/BenchmarkTest00002.java#file:src/main/java/org/example/BenchmarkTest00002.java#type:BenchmarkTest00002#method:doPost/0/#range:0-1"


def _write_context_source(root: Path, relative: Path, class_name: str) -> tuple[Path, str, str]:
    source = root / relative
    source.parent.mkdir(parents=True, exist_ok=True)
    content = f"package org.example;\nclass {class_name} {{ void doPost() {{ }} }}\n".encode()
    source.write_bytes(content)
    snapshot = create_source_snapshot_from_bytes(
        workspace_root=root,
        source_path=source,
        source_bytes=content,
        method_selector=f"org.example.{class_name}#doPost()",
        expected_source_sha256=sha256_hex(content),
    )
    return source, f"workspace@revision:{snapshot.identity.canonical_key}", snapshot.file_sha256


def _unique_build_root(name: str) -> Path:
    return Path("build") / f"{name}-{uuid.uuid4().hex}"


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

        result = remediation.get_violation_context("ISO-A.10-WEAK-HASH", method_key=FIRST_METHOD_KEY)

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

        result = remediation.get_violation_context("ISO-A.10-WEAK-HASH", method_key=FIRST_METHOD_KEY, file_path=benchmark_file)

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
        root = _unique_build_root("remediation-context-cache").resolve()
        shutil.rmtree(root, ignore_errors=True)
        first_file, first_method_key, first_sha = _write_context_source(
            root / "benchmark-a",
            Path("src/main/java/org/example/BenchmarkTest00001.java"),
            "BenchmarkTest00001",
        )
        second_file, second_method_key, second_sha = _write_context_source(
            root / "benchmark-b",
            Path("src/main/java/org/example/BenchmarkTest00002.java"),
            "BenchmarkTest00002",
        )

        first_result = {
            "violations": [
                {
                    "violation_id": "ISO-A.10-WEAK-HASH",
                    "method_key": first_method_key,
                    "target_method": "org.example.BenchmarkTest00001.doPost()",
                    "file_path": first_file.as_posix(),
                    "evidence": {"source_sha256": first_sha},
                }
            ]
        }
        second_result = {
            "violations": [
                {
                    "violation_id": "ISO-A.10-WEAK-HASH",
                    "method_key": second_method_key,
                    "target_method": "org.example.BenchmarkTest00002.doPost()",
                    "file_path": second_file.as_posix(),
                    "evidence": {"source_sha256": second_sha},
                }
            ]
        }

        with (
            patch.object(self.service, "evaluate_policies", side_effect=[first_result, second_result]) as mock_evaluate,
            patch.object(self.service, "load_policy_catalog", return_value={}),
            patch.object(self.service, "build_remediation_plan", return_value={}),
            patch.object(self.service, "PolicyEvaluator") as mock_evaluator,
        ):
            try:
                mock_evaluator.return_value.evaluate.return_value = {"violations": []}

                first_context = remediation.get_violation_context(
                    "ISO-A.10-WEAK-HASH", method_key=first_method_key, file_path=first_file.as_posix()
                )
                second_context = remediation.get_violation_context(
                    "ISO-A.10-WEAK-HASH", method_key=second_method_key, file_path=second_file.as_posix()
                )

                self.assertEqual(mock_evaluate.call_count, 2)
                self.assertEqual(first_context["file_path"], first_file.as_posix())
                self.assertEqual(second_context["file_path"], second_file.as_posix())
                self.assertEqual(first_context["source_sha256"], first_sha)
                self.assertEqual(first_context["expected_source_sha256"], first_sha)
                self.assertEqual(first_context["source_bytes"], first_file.read_bytes())
                self.assertEqual(
                    mock_evaluate.call_args_list[0].kwargs["workspace_root"],
                    first_file.as_posix(),
                )
                self.assertEqual(
                    mock_evaluate.call_args_list[1].kwargs["workspace_root"],
                    second_file.as_posix(),
                )
            finally:
                clear_policy_evaluation_cache()
                shutil.rmtree(root, ignore_errors=True)

    def test_preview_refuses_missing_source_hash_before_generation(self):
        from codegraph.remediation.context import clear_policy_evaluation_cache

        clear_policy_evaluation_cache()
        remediation = self.service.RemediationService(llm_client=lambda _messages, **_: self.fail("LLM must not run"))
        root = _unique_build_root("remediation-context-refusal").resolve()
        shutil.rmtree(root, ignore_errors=True)
        source_file, method_key, _source_sha = _write_context_source(
            root,
            Path("src/main/java/org/example/BenchmarkTest00001.java"),
            "BenchmarkTest00001",
        )
        policy_result = {
            "violations": [
                {
                    "violation_id": "ISO-A.10-WEAK-HASH",
                    "method_key": method_key,
                    "target_method": "org.example.BenchmarkTest00001.doPost()",
                    "file_path": source_file.as_posix(),
                    "evidence": {},
                }
            ]
        }

        try:
            with (
                patch.object(self.service, "evaluate_policies", return_value=policy_result),
                patch.object(self.service, "load_policy_catalog", return_value={}),
            ):
                result = remediation.preview_virtual_fix(
                    "ISO-A.10-WEAK-HASH",
                    method_key=method_key,
                    file_path=source_file.as_posix(),
                )
        finally:
            clear_policy_evaluation_cache()
            shutil.rmtree(root, ignore_errors=True)

        self.assertEqual(result["status"], "STALE_SOURCE")
        self.assertEqual(result["error"], "missing_source_sha256")
        self.assertEqual(result["method_key"], method_key)

    def test_preview_refuses_same_length_stale_source_before_generation(self):
        from codegraph.remediation.context import clear_policy_evaluation_cache

        clear_policy_evaluation_cache()
        remediation = self.service.RemediationService(llm_client=lambda _messages, **_: self.fail("LLM must not run"))
        root = _unique_build_root("remediation-context-refusal").resolve()
        shutil.rmtree(root, ignore_errors=True)
        source_file, method_key, original_sha = _write_context_source(
            root,
            Path("src/main/java/org/example/BenchmarkTest00001.java"),
            "BenchmarkTest00001",
        )
        source_file.write_text("package org.example;\nclass BenchmarkTest00001 { void doPost() {;} }\n", encoding="utf-8")
        policy_result = {
            "violations": [
                {
                    "violation_id": "ISO-A.10-WEAK-HASH",
                    "method_key": method_key,
                    "target_method": "org.example.BenchmarkTest00001.doPost()",
                    "file_path": source_file.as_posix(),
                    "evidence": {"source_sha256": original_sha},
                }
            ]
        }

        try:
            with (
                patch.object(self.service, "evaluate_policies", return_value=policy_result),
                patch.object(self.service, "load_policy_catalog", return_value={}),
            ):
                result = remediation.preview_virtual_fix(
                    "ISO-A.10-WEAK-HASH",
                    method_key=method_key,
                    file_path=source_file.as_posix(),
                )
        finally:
            clear_policy_evaluation_cache()
            shutil.rmtree(root, ignore_errors=True)

        self.assertEqual(result["status"], "STALE_SOURCE")
        self.assertEqual(result["error"], "source_sha256_mismatch")
        self.assertEqual(result["method_key"], method_key)

    def test_preview_surfaces_baseline_evaluation_error_before_generation(self):
        from codegraph.remediation.context import clear_policy_evaluation_cache

        clear_policy_evaluation_cache()
        remediation = self.service.RemediationService(llm_client=lambda _messages, **_: self.fail("LLM must not run"))
        root = _unique_build_root("remediation-context-baseline").resolve()
        shutil.rmtree(root, ignore_errors=True)
        source_file, method_key, source_sha = _write_context_source(
            root,
            Path("src/main/java/org/example/BenchmarkTest00001.java"),
            "BenchmarkTest00001",
        )
        policy_result = {
            "violations": [
                {
                    "violation_id": "ISO-A.10-WEAK-HASH",
                    "method_key": method_key,
                    "target_method": "org.example.BenchmarkTest00001.doPost()",
                    "file_path": source_file.as_posix(),
                    "evidence": {"source_sha256": source_sha},
                }
            ]
        }

        try:
            with (
                patch.object(self.service, "evaluate_policies", return_value=policy_result),
                patch.object(self.service, "load_policy_catalog", return_value={}),
                patch.object(self.service, "PolicyEvaluator") as mock_evaluator,
            ):
                mock_evaluator.return_value.evaluate.return_value = {"error": "method_not_found", "violations": []}
                result = remediation.preview_virtual_fix(
                    "ISO-A.10-WEAK-HASH",
                    method_key=method_key,
                    file_path=source_file.as_posix(),
                )
                mock_evaluator.return_value.evaluate.assert_called_once_with(method_key)
        finally:
            clear_policy_evaluation_cache()
            shutil.rmtree(root, ignore_errors=True)

        self.assertEqual(result["status"], "VERIFICATION_ERROR")
        self.assertEqual(result["error"], "baseline_evaluation_error: method_not_found")
        self.assertEqual(result["method_key"], method_key)

    def test_preview_refuses_method_key_source_path_mismatch(self):
        from codegraph.remediation.context import clear_policy_evaluation_cache

        clear_policy_evaluation_cache()
        remediation = self.service.RemediationService(llm_client=lambda _messages, **_: self.fail("LLM must not run"))
        root = _unique_build_root("remediation-context-path-mismatch").resolve()
        shutil.rmtree(root, ignore_errors=True)
        source_file, method_key, source_sha = _write_context_source(
            root,
            Path("src/main/java/org/example/BenchmarkTest00001.java"),
            "BenchmarkTest00001",
        )
        mismatched_key = method_key.replace(
            "src/main/java/org/example/BenchmarkTest00001.java",
            "src/main/java/org/example/Other.java",
            1,
        )
        policy_result = {
            "violations": [
                {
                    "violation_id": "ISO-A.10-WEAK-HASH",
                    "method_key": mismatched_key,
                    "target_method": "org.example.BenchmarkTest00001.doPost()",
                    "file_path": source_file.as_posix(),
                    "evidence": {"source_sha256": source_sha},
                }
            ]
        }

        try:
            with (
                patch.object(self.service, "evaluate_policies", return_value=policy_result),
                patch.object(self.service, "load_policy_catalog", return_value={}),
            ):
                result = remediation.preview_virtual_fix(
                    "ISO-A.10-WEAK-HASH",
                    method_key=mismatched_key,
                    file_path=source_file.as_posix(),
                )
        finally:
            clear_policy_evaluation_cache()
            shutil.rmtree(root, ignore_errors=True)

        self.assertEqual(result["status"], "STALE_SOURCE")
        self.assertEqual(result["error"], "method_key_source_path_mismatch")
        self.assertEqual(result["method_key"], mismatched_key)


if __name__ == "__main__":
    unittest.main()
