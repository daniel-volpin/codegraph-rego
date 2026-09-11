import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from codegraph.remediation import apply_flow as apply_flow_mod
from tests.codegraph.remediation._test_helpers import (
    ProposalResponseBuilder,
    RemediationTestBase,
    ViolationContextBuilder,
)


class ApplyFixTests(RemediationTestBase):
    def test_apply_fix_returns_generation_error_for_invalid_structured_output(self):
        svc_mod = self.service
        with TemporaryDirectory() as tmp:
            src_path = Path(tmp) / "Example.java"
            src_path.write_text("class Example { void hash() {} }\n", encoding="utf-8")

            context = ViolationContextBuilder().with_file_path(src_path.as_posix()).build()

            error_response = ProposalResponseBuilder().with_error('invalid_java_syntax: expected ")"').build()

            remediation = svc_mod.RemediationService(llm_client=lambda *_args, **_kwargs: "")
            remediation.get_violation_context = lambda *_args, **_kwargs: context  # type: ignore[method-assign]
            remediation._resolve_file_path = lambda *_args, **_kwargs: src_path  # type: ignore[method-assign]
            remediation.propose_method_edits = lambda *_args, **_kwargs: error_response  # type: ignore[method-assign]

            out = remediation.apply_fix(
                "ISO-A.10-WEAK-HASH",
                target_method="com.example.Foo.hash()",
                file_path=src_path.as_posix(),
                mode="dry_run",
                max_attempts=1,
            )
            self.assertEqual(out.get("status"), "GENERATION_ERROR")
            self.assertIn("invalid_java_syntax", out.get("error", ""))
            self.assertIn("invalid_java_syntax", out.get("errors", []))

    def test_retry_error_summary_is_structural(self):
        self.assertEqual(
            self.service._summarize_retry_error("invalid_java_syntax: JavaSyntaxError"), "invalid_java_syntax"
        )
        self.assertEqual(self.service._summarize_retry_error("method_name_mismatch"), "method_name_mismatch")
        self.assertEqual(
            self.service._summarize_retry_error("Failed to produce a valid method replacement"),
            "replacement_not_found",
        )

    def test_apply_fix_dry_run_uses_temp_source_without_live_file_write(self):
        svc_mod = self.service

        with TemporaryDirectory() as tmp:
            src_path = Path(tmp) / "Example.java"
            original_content = "class Example { void a() {} }\n"
            updated_content = "class Example { void a() { /* UPDATED */ } }\n"
            updated_method = "void a() { /* UPDATED */ }"
            src_path.write_text(original_content, encoding="utf-8")

            target_method = (
                "org.owasp.benchmark.testcode.BenchmarkTest00272.doPost(HttpServletRequest,HttpServletResponse)"
            )

            context = (
                ViolationContextBuilder()
                .with_target_method(target_method)
                .with_file_path(src_path.as_posix())
                .with_source_code('public void doPost(...) { MessageDigest.getInstance("MD5"); }')
                .with_exact_method_source('public void doPost(...) { MessageDigest.getInstance("MD5"); }')
                .build()
            )

            proposal_response = (
                ProposalResponseBuilder()
                .with_edits(
                    original_lines=['public void doPost(...) { MessageDigest.getInstance("MD5"); }'],
                    replacement_lines=["public void doPost(...) { /* sha-256 */ }"],
                )
                .build()
            )

            remediation = svc_mod.RemediationService(llm_client=lambda *_args, **_kwargs: "")
            remediation.get_violation_context = lambda *_args, **_kwargs: context  # type: ignore[method-assign]
            remediation._resolve_file_path = lambda *_args, **_kwargs: src_path  # type: ignore[method-assign]
            remediation.propose_method_edits = lambda *_args, **_kwargs: proposal_response  # type: ignore[method-assign]
            remediation._replace_method_in_source = (  # type: ignore[method-assign]
                lambda *_args, **_kwargs: (updated_content, "void a() {}", updated_method)
            )

            def _prepare_temp_workspace(tmp_root, _resolved):
                temp_file = Path(tmp_root) / "isolated" / "Example.java"
                temp_file.parent.mkdir(parents=True, exist_ok=True)
                return Path(tmp_root), temp_file, Path(tmp_root)

            remediation._prepare_temp_workspace = _prepare_temp_workspace  # type: ignore[method-assign]
            remediation._compile_project = (  # type: ignore[method-assign]
                lambda *_args, **_kwargs: {
                    "attempted": False,
                    "success": False,
                    "output_snippet": None,
                    "skipped_reason": "test",
                }
            )

            captured: dict[str, object] = {
                "reingest_calls": [],
                "source_path_override": None,
                "temp_file_content": None,
            }

            class RecordingPolicyEvaluator:
                def evaluate(self, _method_signature: str, *, source_path_override: str | None = None):
                    captured["source_path_override"] = source_path_override
                    if source_path_override:
                        captured["temp_file_content"] = Path(source_path_override).read_text(encoding="utf-8")
                    return {"violations": []}

            def reingest_side_effect(path: str, content: str) -> None:
                captured["reingest_calls"].append((path, content))

            with (
                patch.object(apply_flow_mod, "process_single_file_content", side_effect=reingest_side_effect),
                patch.object(apply_flow_mod, "PolicyEvaluator", RecordingPolicyEvaluator),
            ):
                out = remediation.apply_fix(
                    "ISO-A.10-WEAK-HASH",
                    target_method=target_method,
                    file_path=src_path.as_posix(),
                    mode="dry_run",
                    max_attempts=1,
                )
                self.assertEqual(out.get("status"), "OK")
                self.assertEqual(out.get("updated_source_code"), updated_method)
                self.assertEqual(out.get("metadata", {}).get("mode"), "dry_run")
                self.assertEqual(src_path.read_text(encoding="utf-8"), original_content)
                self.assertNotEqual(captured["source_path_override"], src_path.as_posix())
                self.assertEqual(captured["temp_file_content"], updated_content)
                self.assertEqual(
                    captured["reingest_calls"],
                    [
                        (src_path.as_posix(), updated_content),
                        (src_path.as_posix(), original_content),
                    ],
                )

    def test_apply_fix_restores_original_file_on_verification_exception(self):
        svc_mod = self.service

        with TemporaryDirectory() as tmp:
            src_path = Path(tmp) / "Example.java"
            original_content = "class Example { void a() {} }\n"
            src_path.write_text(original_content, encoding="utf-8")

            target_method = (
                "org.owasp.benchmark.testcode.BenchmarkTest00272.doPost(HttpServletRequest,HttpServletResponse)"
            )

            context = (
                ViolationContextBuilder()
                .with_target_method(target_method)
                .with_file_path(src_path.as_posix())
                .with_source_code('public void doPost(...) { MessageDigest.getInstance("MD5"); }')
                .with_exact_method_source('public void doPost(...) { MessageDigest.getInstance("MD5"); }')
                .build()
            )

            proposal_response = (
                ProposalResponseBuilder()
                .with_edits(
                    original_lines=['public void doPost(...) { MessageDigest.getInstance("MD5"); }'],
                    replacement_lines=["public void doPost(...) { /* sha-256 */ }"],
                )
                .build()
            )

            remediation = svc_mod.RemediationService(llm_client=lambda *_args, **_kwargs: "")
            remediation.get_violation_context = lambda *_args, **_kwargs: context  # type: ignore[method-assign]
            remediation._resolve_file_path = lambda *_args, **_kwargs: src_path  # type: ignore[method-assign]
            remediation.propose_method_edits = lambda *_args, **_kwargs: proposal_response  # type: ignore[method-assign]
            remediation._replace_method_in_source = (  # type: ignore[method-assign]
                lambda *_args, **_kwargs: (
                    "class Example { void a() { /* UPDATED */ } }\n",
                    "void a() {}",
                    "void a() { /* UPDATED */ }",
                )
            )
            remediation._prepare_temp_workspace = (  # type: ignore[method-assign]
                lambda tmp_root, _resolved: (tmp_root, Path(tmp_root) / "Example.java", Path(tmp_root))
            )
            remediation._compile_project = (  # type: ignore[method-assign]
                lambda *_args, **_kwargs: {
                    "attempted": False,
                    "success": False,
                    "output_snippet": None,
                    "skipped_reason": "test",
                }
            )

            reingest_calls: list[tuple[str, str]] = []
            source_path_overrides: list[str | None] = []

            class BoomPolicyEvaluator:
                def evaluate(self, _method_signature: str, *, source_path_override: str | None = None):
                    source_path_overrides.append(source_path_override)
                    raise RuntimeError("boom")

            def reingest_side_effect(path: str, content: str) -> None:
                reingest_calls.append((path, content))

            with (
                patch.object(apply_flow_mod, "process_single_file_content", side_effect=reingest_side_effect),
                patch.object(apply_flow_mod, "PolicyEvaluator", BoomPolicyEvaluator),
            ):
                out = remediation.apply_fix(
                    "ISO-A.10-WEAK-HASH",
                    target_method=target_method,
                    file_path=src_path.as_posix(),
                    mode="dry_run",
                    max_attempts=1,
                )
                self.assertEqual(out.get("status"), "VERIFICATION_ERROR")
                self.assertEqual(src_path.read_text(encoding="utf-8"), original_content)
                self.assertEqual(len(source_path_overrides), 1)
                self.assertIsNotNone(source_path_overrides[0])
                self.assertNotEqual(source_path_overrides[0], src_path.as_posix())
                self.assertEqual(Path(str(source_path_overrides[0])).name, "Example.java")
                self.assertEqual(
                    reingest_calls,
                    [
                        (src_path.as_posix(), "class Example { void a() { /* UPDATED */ } }\n"),
                        (src_path.as_posix(), original_content),
                    ],
                )
    def _build_remediation_for_apply(self, svc_mod, src_path, updated_content, target_method, *, compile_result):
        context = (
            ViolationContextBuilder()
            .with_target_method(target_method)
            .with_file_path(src_path.as_posix())
            .with_source_code('public void doPost(...) { MessageDigest.getInstance("MD5"); }')
            .with_exact_method_source('public void doPost(...) { MessageDigest.getInstance("MD5"); }')
            .build()
        )
        proposal_response = (
            ProposalResponseBuilder()
            .with_edits(
                original_lines=['public void doPost(...) { MessageDigest.getInstance("MD5"); }'],
                replacement_lines=["public void doPost(...) { /* sha-256 */ }"],
            )
            .build()
        )
        remediation = svc_mod.RemediationService(llm_client=lambda *_a, **_k: "")
        remediation.get_violation_context = lambda *_a, **_k: context  # type: ignore[method-assign]
        remediation._resolve_file_path = lambda *_a, **_k: src_path  # type: ignore[method-assign]
        remediation.propose_method_edits = lambda *_a, **_k: proposal_response  # type: ignore[method-assign]
        remediation._replace_method_in_source = (  # type: ignore[method-assign]
            lambda *_a, **_k: (updated_content, "void a() {}", "void a() { /* UPDATED */ }")
        )
        remediation._prepare_temp_workspace = (  # type: ignore[method-assign]
            lambda tmp_root, _resolved: (tmp_root, Path(tmp_root) / "Example.java", Path(tmp_root))
        )
        remediation._compile_project = lambda *_a, **_k: compile_result  # type: ignore[method-assign]
        return remediation

    def test_apply_mode_does_not_write_when_build_skipped(self):
        """Fail-closed gate: a skipped build must not authorize a live apply (REM-F3)."""
        svc_mod = self.service
        with TemporaryDirectory() as tmp:
            src_path = Path(tmp) / "Example.java"
            original_content = "class Example { void a() {} }\n"
            updated_content = "class Example { void a() { /* UPDATED */ } }\n"
            src_path.write_text(original_content, encoding="utf-8")
            target_method = "org.example.Foo.doPost(HttpServletRequest,HttpServletResponse)"
            remediation = self._build_remediation_for_apply(
                svc_mod,
                src_path,
                updated_content,
                target_method,
                compile_result={
                    "attempted": False,
                    "success": False,
                    "output_snippet": None,
                    "skipped_reason": "No build system detected",
                },
            )

            class PassPolicyEvaluator:
                def evaluate(self, _m, *, source_path_override=None):
                    return {"violations": []}

            with (
                patch.object(apply_flow_mod, "process_single_file_content", side_effect=lambda *_a, **_k: None),
                patch.object(apply_flow_mod, "PolicyEvaluator", PassPolicyEvaluator),
            ):
                out = remediation.apply_fix(
                    "ISO-A.10-WEAK-HASH",
                    target_method=target_method,
                    file_path=src_path.as_posix(),
                    mode="apply",
                    max_attempts=1,
                )
            self.assertNotEqual(out.get("status"), "OK")
            self.assertEqual(out.get("status"), "VERIFICATION_ERROR")
            # The live file must be restored to its original content.
            self.assertEqual(src_path.read_text(encoding="utf-8"), original_content)

    def test_rollback_failure_downgrades_status(self):
        """A failed restore must not be reported as a clean success (REM-F9)."""
        svc_mod = self.service
        with TemporaryDirectory() as tmp:
            src_path = Path(tmp) / "Example.java"
            original_content = "class Example { void a() {} }\n"
            updated_content = "class Example { void a() { /* UPDATED */ } }\n"
            src_path.write_text(original_content, encoding="utf-8")
            target_method = "org.example.Foo.doPost(HttpServletRequest,HttpServletResponse)"
            remediation = self._build_remediation_for_apply(
                svc_mod,
                src_path,
                updated_content,
                target_method,
                compile_result={
                    "attempted": False,
                    "success": False,
                    "output_snippet": None,
                    "skipped_reason": "test",
                },
            )

            class PassPolicyEvaluator:
                def evaluate(self, _m, *, source_path_override=None):
                    return {"violations": []}

            calls: list[int] = []

            def reingest(_path: str, _content: str) -> None:
                calls.append(1)
                if len(calls) == 2:  # the restore call in the finally block
                    raise RuntimeError("restore boom")

            with (
                patch.object(apply_flow_mod, "process_single_file_content", side_effect=reingest),
                patch.object(apply_flow_mod, "PolicyEvaluator", PassPolicyEvaluator),
            ):
                out = remediation.apply_fix(
                    "ISO-A.10-WEAK-HASH",
                    target_method=target_method,
                    file_path=src_path.as_posix(),
                    mode="dry_run",
                    max_attempts=1,
                )
            self.assertEqual(out.get("status"), "VERIFICATION_ERROR")
            self.assertIn("Rollback failed", out.get("error", ""))

    def test_graph_rollback_failure_does_not_skip_file_restoration(self):
        with TemporaryDirectory() as tmp:
            src_path = Path(tmp) / "Example.java"
            original = "class Example { void a() {} }\n"
            candidate = "class Example { void a() { /* candidate */ } }\n"
            src_path.write_text(original, encoding="utf-8")
            remediation = self._build_remediation_for_apply(
                self.service, src_path, candidate, "org.example.Foo.doPost()",
                compile_result={"attempted": False, "success": False},
            )

            class Evaluator:
                def trace(self, *_args, **_kwargs):
                    return {}

                def evaluate(self, *_args, **_kwargs):
                    return {"violations": []}

            with (
                patch.object(apply_flow_mod, "PolicyEvaluator", Evaluator),
                patch.object(
                    apply_flow_mod, "process_single_file_content",
                    side_effect=[None, RuntimeError("graph rollback unavailable")],
                ),
            ):
                result = remediation.apply_fix("ISO-A.10-WEAK-HASH", mode="apply", max_attempts=1)

            self.assertEqual(src_path.read_text(encoding="utf-8"), original)
            self.assertEqual(result["status"], "VERIFICATION_ERROR")
            self.assertEqual(result["verification"]["cleanup"], {"graph_restored": False, "file_restored": True})

    def test_cleanup_failures_are_reported_after_candidate_failure(self):
        for failing_stage in ("ingestion", "evaluation"):
            with self.subTest(stage=failing_stage), TemporaryDirectory() as tmp:
                src_path = Path(tmp) / "Example.java"
                original = "class Example { void a() {} }\n"
                candidate = "class Example { void a() { /* candidate */ } }\n"
                src_path.write_text(original, encoding="utf-8")
                remediation = self._build_remediation_for_apply(
                    self.service, src_path, candidate, "org.example.Foo.doPost()",
                    compile_result={"attempted": True, "success": True},
                )

                class Evaluator:
                    def trace(self, *_args, **_kwargs):
                        return {}

                    def evaluate(self, *_args, **_kwargs):
                        raise RuntimeError("candidate evaluation failed")

                initial_outcome = RuntimeError("candidate ingestion failed") if failing_stage == "ingestion" else None
                with (
                    patch.object(apply_flow_mod, "PolicyEvaluator", Evaluator),
                    patch.object(
                        apply_flow_mod, "process_single_file_content",
                        side_effect=[initial_outcome, RuntimeError("graph rollback unavailable")],
                    ),
                ):
                    result = remediation.apply_fix("ISO-A.10-WEAK-HASH", mode="apply", max_attempts=1)

                self.assertEqual(src_path.read_text(encoding="utf-8"), original)
                self.assertEqual(result["status"], "VERIFICATION_ERROR")
                self.assertIn(f"candidate {failing_stage} failed", result["error"])
                self.assertIn("Rollback failed", result["error"])
                self.assertEqual(result["verification"]["cleanup"], {"graph_restored": False, "file_restored": True})


if __name__ == "__main__":
    unittest.main()
