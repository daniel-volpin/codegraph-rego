import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from codegraph.ingestion.snapshots import create_source_snapshot_from_bytes, sha256_hex
from codegraph.remediation import apply_flow as apply_flow_mod
from codegraph.remediation.candidate import build_candidate_overlay
from tests.codegraph.remediation._test_helpers import (
    ProposalResponseBuilder,
    RemediationTestBase,
    ViolationContextBuilder,
)


def _method_context(root: Path, rel: Path, source: str, replacement_method: str | None = None):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    snapshot = create_source_snapshot_from_bytes(
        workspace_root=root,
        source_path=path,
        source_bytes=source.encode("utf-8"),
        method_selector=("demo.Example#hash()" if "package demo;" in source else "Example#hash()"),
        expected_source_sha256=sha256_hex(source.encode("utf-8")),
    )
    method_key = f"workspace@revision:{rel.as_posix()}#{snapshot.identity.source_key}"
    context = {
        "violation": {"violation_id": "ISO-A.10-WEAK-HASH", "reason": "test"},
        "method_key": method_key,
        "target_method": snapshot.identity.syntactic_signature,
        "file_path": path.as_posix(),
        "rule_id": "ISO-A.10-WEAK-HASH",
        "evidence": {
            "source_code": snapshot.method_source,
            "source_code_raw": snapshot.method_source,
            "parser": {"source_sha256": snapshot.file_sha256},
            "source_sha256": snapshot.file_sha256,
            "graph_context": {},
            "vector_context": [],
        },
        "catalog_entry": {"title": "Test"},
        "baseline_violations": [],
        "exact_method_source": snapshot.method_source,
    }
    overlay = None
    if replacement_method is not None:
        overlay = build_candidate_overlay(snapshot, replacement_method.encode("utf-8"))
    return path, context, snapshot, overlay


class ApplyFixTests(RemediationTestBase):
    def test_dry_run_verifies_candidate_inside_isolated_workspace_and_leaves_source_untouched(self):
        svc_mod = self.service
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = "package demo;\nclass Example {\n  void hash() throws Exception {\n    java.security.MessageDigest.getInstance(\"MD5\");\n  }\n}\n"
            replacement_method = "void hash() throws Exception {\n    java.security.MessageDigest.getInstance(\"SHA-256\");\n  }"
            src_path, context, _snapshot, overlay = _method_context(root, Path("src/Example.java"), original, replacement_method)
            assert overlay is not None

            remediation = svc_mod.RemediationService(llm_client=lambda *_args, **_kwargs: "")
            remediation.get_violation_context = lambda *_args, **_kwargs: context  # type: ignore[method-assign]
            remediation._resolve_file_path = lambda *_args, **_kwargs: src_path  # type: ignore[method-assign]
            remediation.propose_method_edits = lambda *_args, **_kwargs: (  # type: ignore[method-assign]
                ProposalResponseBuilder().with_edits(replacement_lines=replacement_method.splitlines()).build()
            )
            remediation._prepare_temp_workspace = (  # type: ignore[method-assign]
                lambda tmp_root, _resolved: (
                    tmp_root,
                    Path(tmp_root) / "src" / "Example.java",
                    tmp_root,
                )
            )
            remediation._compile_project = lambda *_args, **_kwargs: {"attempted": True, "success": True}  # type: ignore[method-assign]
            captured: dict[str, object] = {}

            def fake_verify_candidate(**kwargs):
                captured.update(kwargs)
                workspace = Path(kwargs["workspace_root"]).resolve()
                candidate = (workspace / kwargs["candidate"]).resolve()
                source = (workspace / kwargs["source"]).resolve()
                candidate.relative_to(workspace)
                source.relative_to(workspace)
                self.assertEqual(source.read_bytes(), original.encode("utf-8"))
                self.assertEqual(candidate.read_bytes(), overlay.candidate_method_bytes)
                return {"status": "POLICY_PASS", "policy_status": "PASS"}

            with patch.object(apply_flow_mod, "verify_candidate", side_effect=fake_verify_candidate):
                result = remediation.apply_fix(
                    context["rule_id"],
                    method_key=context["method_key"],
                    file_path=src_path.as_posix(),
                    mode="dry_run",
                    max_attempts=1,
                )

            self.assertEqual(result["status"], "OK", result)
            self.assertEqual(src_path.read_text(encoding="utf-8"), original)
            self.assertEqual(captured["source"], Path("src/Example.java"))
            self.assertEqual(captured["method_selector"], context["method_key"])
            self.assertEqual(captured["expected_source_sha256"], context["evidence"]["source_sha256"])

    def test_apply_commits_exact_verified_candidate_bytes_and_not_normalized_text_replacement(self):
        svc_mod = self.service
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = "package demo;\r\nclass Example {\r\n  void hash() throws Exception {\r\n    java.security.MessageDigest.getInstance(\"MD5\");\r\n  }\r\n}\r\n"
            replacement_method = "void hash() throws Exception {\n    java.security.MessageDigest.getInstance(\"SHA-256\");\n  }"
            src_path, context, _snapshot, overlay = _method_context(root, Path("src/Example.java"), original, replacement_method)
            assert overlay is not None
            compiled: dict[str, bytes] = {}

            remediation = svc_mod.RemediationService(llm_client=lambda *_args, **_kwargs: "")
            remediation.get_violation_context = lambda *_args, **_kwargs: context  # type: ignore[method-assign]
            remediation._resolve_file_path = lambda *_args, **_kwargs: src_path  # type: ignore[method-assign]
            remediation.propose_method_edits = lambda *_args, **_kwargs: (  # type: ignore[method-assign]
                ProposalResponseBuilder().with_edits(replacement_lines=replacement_method.splitlines()).build()
            )
            remediation._prepare_temp_workspace = (  # type: ignore[method-assign]
                lambda tmp_root, _resolved: (
                    tmp_root,
                    Path(tmp_root) / "src" / "Example.java",
                    tmp_root,
                )
            )

            def compile_project(build_root, **_kwargs):
                compiled["bytes"] = (Path(build_root) / "src" / "Example.java").read_bytes()
                return {"attempted": True, "success": True}

            remediation._compile_project = compile_project  # type: ignore[method-assign]

            with (
                patch.object(apply_flow_mod, "verify_candidate", return_value={"status": "POLICY_PASS"}),
                patch.object(apply_flow_mod, "ingest", return_value=object()),
            ):
                result = remediation.apply_fix(
                    context["rule_id"],
                    method_key=context["method_key"],
                    file_path=src_path.as_posix(),
                    mode="apply",
                    max_attempts=1,
                )

            self.assertEqual(result["status"], "OK", result)
            self.assertEqual(compiled["bytes"], overlay.candidate_file_bytes)
            self.assertEqual(src_path.read_bytes(), overlay.candidate_file_bytes)

    def test_stale_original_after_verification_blocks_dry_run_ok_and_apply_write(self):
        svc_mod = self.service
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = "package demo;\nclass Example {\n  void hash() throws Exception {\n    java.security.MessageDigest.getInstance(\"MD5\");\n  }\n}\n"
            replacement_method = "void hash() throws Exception {\n    java.security.MessageDigest.getInstance(\"SHA-256\");\n  }"
            src_path, context, _snapshot, _overlay = _method_context(root, Path("src/Example.java"), original, replacement_method)

            remediation = svc_mod.RemediationService(llm_client=lambda *_args, **_kwargs: "")
            remediation.get_violation_context = lambda *_args, **_kwargs: context  # type: ignore[method-assign]
            remediation._resolve_file_path = lambda *_args, **_kwargs: src_path  # type: ignore[method-assign]
            remediation.propose_method_edits = lambda *_args, **_kwargs: (  # type: ignore[method-assign]
                ProposalResponseBuilder().with_edits(replacement_lines=replacement_method.splitlines()).build()
            )
            remediation._compile_project = lambda *_args, **_kwargs: {"attempted": True, "success": True}  # type: ignore[method-assign]

            def verify_and_race(**_kwargs):
                src_path.write_text(original.replace("MD5", "SHA-1"), encoding="utf-8")
                return {"status": "POLICY_PASS"}

            with (
                patch.object(apply_flow_mod, "verify_candidate", side_effect=verify_and_race),
                patch.object(apply_flow_mod, "ingest", side_effect=AssertionError("stale source must not publish")),
            ):
                result = remediation.apply_fix(
                    context["rule_id"],
                    method_key=context["method_key"],
                    file_path=src_path.as_posix(),
                    mode="apply",
                    max_attempts=1,
                )

            self.assertEqual(result["status"], "VERIFICATION_ERROR")
            self.assertEqual(result["verification"]["status"], "STALE_CANDIDATE")
            self.assertIn("SHA-1", src_path.read_text(encoding="utf-8"))

    def test_workspace_root_mismatch_is_refused(self):
        with TemporaryDirectory() as tmp:
            src_path = Path(tmp) / "other" / "Example.java"
            src_path.parent.mkdir(parents=True)
            src_path.write_text("class Example { void hash() {} }\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "source_path_method_key_mismatch"):
                apply_flow_mod._workspace_root_for(src_path, "workspace@revision:src/Example.java#file:src/Example.java#method:hash/0")

    def test_missing_evidence_source_hash_is_explicit_refusal(self):
        svc_mod = self.service
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            original = "class Example { void hash() {} }\n"
            src_path, context, _snapshot, _overlay = _method_context(root, Path("Example.java"), original)
            del context["evidence"]["source_sha256"]

            remediation = svc_mod.RemediationService(llm_client=lambda *_args, **_kwargs: "")
            remediation.get_violation_context = lambda *_args, **_kwargs: context  # type: ignore[method-assign]
            remediation._resolve_file_path = lambda *_args, **_kwargs: src_path  # type: ignore[method-assign]

            result = remediation.apply_fix(
                context["rule_id"],
                method_key=context["method_key"],
                file_path=src_path.as_posix(),
                mode="dry_run",
                max_attempts=1,
            )

            self.assertEqual(result["status"], "VERIFICATION_ERROR")
            self.assertEqual(result["error"], "evidence.source_sha256 is required")

    def test_apply_fix_uses_method_key_and_scoped_verification_without_graph_writes(self):
        svc_mod = self.service
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            original_content = "package demo;\nclass Example {\n  void hash() throws Exception {\n    java.security.MessageDigest.getInstance(\"MD5\");\n  }\n}\n"
            replacement_method = "void hash() throws Exception {\n    java.security.MessageDigest.getInstance(\"SHA-256\");\n  }"
            src_path, context, _snapshot, _overlay = _method_context(
                root, Path("src/Example.java"), original_content, replacement_method
            )
            proposal_response = ProposalResponseBuilder().with_edits(
                replacement_lines=replacement_method.splitlines(),
            ).build()

            remediation = svc_mod.RemediationService(llm_client=lambda *_args, **_kwargs: "")
            remediation.get_violation_context = lambda *_args, **_kwargs: context  # type: ignore[method-assign]
            remediation._resolve_file_path = lambda *_args, **_kwargs: src_path  # type: ignore[method-assign]
            remediation.propose_method_edits = lambda *_args, **_kwargs: proposal_response  # type: ignore[method-assign]
            remediation._compile_project = lambda *_args, **_kwargs: {"attempted": True, "success": True}  # type: ignore[method-assign]
            captured: dict[str, object] = {}

            def fake_verify(**kwargs):
                captured.update(kwargs)
                captured["candidate_source"] = (Path(kwargs["workspace_root"]) / kwargs["candidate"]).read_text(encoding="utf-8")
                return {
                    "status": "POLICY_PASS",
                    "policy_status": "PASS",
                    "target_rule_status": "PASS",
                    "rule_id": kwargs["rule_id"],
                    "baseline": {},
                    "candidate": {},
                    "findings": {"baseline": [], "candidate": []},
                    "policy_summary": {
                        "target_rule_status": "PASS",
                        "new_violations": [],
                        "remaining_baseline_violations": [],
                    },
                }

            with patch.object(apply_flow_mod, "verify_candidate", side_effect=fake_verify):
                out = remediation.apply_fix(
                    "ISO-A.10-WEAK-HASH",
                    method_key=context["method_key"],
                    file_path=src_path.as_posix(),
                    mode="dry_run",
                    max_attempts=1,
                )

            self.assertEqual(out["status"], "OK")
            self.assertEqual(out["method_key"], context["method_key"])
            self.assertEqual(out["metadata"]["method_key"], context["method_key"])
            self.assertEqual(captured["method_selector"], context["method_key"])
            self.assertEqual(captured["source"], Path("src/Example.java"))
            self.assertEqual(src_path.read_text(encoding="utf-8"), original_content)
            self.assertIn("SHA-256", captured["candidate_source"])

    def test_apply_fix_returns_generation_error_for_invalid_structured_output(self):
        svc_mod = self.service
        with TemporaryDirectory() as tmp:
            src_path, context, _snapshot, _overlay = _method_context(
                Path(tmp),
                Path("Example.java"),
                "class Example { void hash() {} }\n",
            )

            error_response = ProposalResponseBuilder().with_error('invalid_java_syntax: expected ")"').build()

            remediation = svc_mod.RemediationService(llm_client=lambda *_args, **_kwargs: "")
            remediation.get_violation_context = lambda *_args, **_kwargs: context  # type: ignore[method-assign]
            remediation._resolve_file_path = lambda *_args, **_kwargs: src_path  # type: ignore[method-assign]
            remediation.propose_method_edits = lambda *_args, **_kwargs: error_response  # type: ignore[method-assign]

            out = remediation.apply_fix(
                "ISO-A.10-WEAK-HASH",
                method_key=context["method_key"],
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
            src_path.write_text(original_content, encoding="utf-8")
            remediation = self._build_remediation_for_apply(
                svc_mod,
                src_path,
                updated_content,
                "Example.a()",
                compile_result={"attempted": True, "success": True},
            )

            def _prepare_temp_workspace(tmp_root, _resolved):
                temp_file = Path(tmp_root) / "isolated" / "Example.java"
                temp_file.parent.mkdir(parents=True, exist_ok=True)
                return Path(tmp_root), temp_file, Path(tmp_root)

            remediation._prepare_temp_workspace = _prepare_temp_workspace  # type: ignore[method-assign]
            remediation._compile_project = (  # type: ignore[method-assign]
                lambda *_args, **_kwargs: {
                    "attempted": True,
                    "success": True,
                    "output_snippet": None,
                }
            )

            captured: dict[str, object] = {
                "candidate_method_content": None,
            }

            def verify_candidate(**kwargs):
                captured["candidate_method_content"] = (Path(kwargs["workspace_root"]) / kwargs["candidate"]).read_text(
                    encoding="utf-8"
                )
                return {"status": "POLICY_PASS"}

            with (
                patch.object(apply_flow_mod, "verify_candidate", side_effect=verify_candidate),
            ):
                out = remediation.apply_fix(
                    "ISO-A.10-WEAK-HASH",
                    method_key=remediation.get_violation_context(None)["method_key"],
                    file_path=src_path.as_posix(),
                    mode="dry_run",
                    max_attempts=1,
                )
                self.assertEqual(out.get("status"), "OK", out)
                self.assertIn("UPDATED", out.get("updated_source_code"))
                self.assertEqual(out.get("metadata", {}).get("mode"), "dry_run")
                self.assertEqual(src_path.read_text(encoding="utf-8"), original_content)
                self.assertIn("UPDATED", captured["candidate_method_content"])

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

            with patch.object(apply_flow_mod, "verify_candidate", side_effect=RuntimeError("boom")):
                out = remediation.apply_fix(
                    "ISO-A.10-WEAK-HASH",
                    method_key=context["method_key"],
                    file_path=src_path.as_posix(),
                    mode="dry_run",
                    max_attempts=1,
                )
                self.assertEqual(out.get("status"), "VERIFICATION_ERROR")
                self.assertEqual(src_path.read_text(encoding="utf-8"), original_content)

    def _build_remediation_for_apply(self, svc_mod, src_path, updated_content, target_method, *, compile_result):
        original_bytes = src_path.read_bytes()
        snapshot = create_source_snapshot_from_bytes(
            workspace_root=src_path.parent,
            source_path=src_path,
            source_bytes=original_bytes,
            method_selector="Example#a()",
            expected_source_sha256=sha256_hex(original_bytes),
        )
        candidate_snapshot = create_source_snapshot_from_bytes(
            workspace_root=src_path.parent,
            source_path=src_path,
            source_bytes=updated_content.encode("utf-8"),
            method_selector="Example#a()",
            expected_source_sha256=sha256_hex(updated_content.encode("utf-8")),
        )
        method_key = f"workspace@revision:{src_path.name}#{snapshot.identity.source_key}"
        context = (
            ViolationContextBuilder()
            .with_target_method(target_method)
            .with_method_key(method_key)
            .with_file_path(src_path.as_posix())
            .with_source_code(snapshot.method_source)
            .with_exact_method_source(snapshot.method_source)
            .build()
        )
        context["evidence"]["source_sha256"] = snapshot.file_sha256
        proposal_response = ProposalResponseBuilder().with_edits(
            original_lines=snapshot.method_source.splitlines(),
            replacement_lines=candidate_snapshot.method_source.splitlines(),
        ).build()
        remediation = svc_mod.RemediationService(llm_client=lambda *_a, **_k: "")
        remediation.get_violation_context = lambda *_a, **_k: context  # type: ignore[method-assign]
        remediation._resolve_file_path = lambda *_a, **_k: src_path  # type: ignore[method-assign]
        remediation.propose_method_edits = lambda *_a, **_k: proposal_response  # type: ignore[method-assign]
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

            with (
                patch.object(apply_flow_mod, "verify_candidate", return_value={"status": "POLICY_PASS", "target_rule_status": "PASS"}),
                patch.object(apply_flow_mod, "ingest", side_effect=AssertionError("build skip must not publish")),
            ):
                out = remediation.apply_fix(
                    "ISO-A.10-WEAK-HASH",
                    method_key=remediation.get_violation_context(None)["method_key"],
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

            with patch.object(apply_flow_mod, "verify_candidate", return_value={"status": "POLICY_FAIL", "target_rule_status": "FAIL"}):
                out = remediation.apply_fix(
                    "ISO-A.10-WEAK-HASH",
                    method_key=remediation.get_violation_context(None)["method_key"],
                    file_path=src_path.as_posix(),
                    mode="dry_run",
                    max_attempts=1,
                )
            self.assertNotEqual(out.get("status"), "OK")
            self.assertEqual(src_path.read_text(encoding="utf-8"), original_content)
            self.assertEqual(out["verification"]["cleanup"], {"file_restored": None, "revision_published": None})

    def test_no_graph_rollback_hook_is_required_for_file_restoration(self):
        with TemporaryDirectory() as tmp:
            src_path = Path(tmp) / "Example.java"
            original = "class Example { void a() {} }\n"
            candidate = "class Example { void a() { /* candidate */ } }\n"
            src_path.write_text(original, encoding="utf-8")
            remediation = self._build_remediation_for_apply(
                self.service, src_path, candidate, "org.example.Foo.doPost()",
                compile_result={"attempted": True, "success": True},
            )

            with (
                patch.object(apply_flow_mod, "verify_candidate", return_value={"status": "POLICY_PASS", "target_rule_status": "PASS"}),
                patch.object(apply_flow_mod, "ingest", side_effect=RuntimeError("publication failed")),
            ):
                result = remediation.apply_fix(
                    "ISO-A.10-WEAK-HASH",
                    method_key=remediation.get_violation_context(None)["method_key"],
                    mode="apply",
                    max_attempts=1,
                )

            self.assertEqual(src_path.read_text(encoding="utf-8"), original)
            self.assertEqual(result["status"], "VERIFICATION_ERROR")
            self.assertEqual(result["verification"]["cleanup"], {"file_restored": True, "revision_published": None})

    def test_cleanup_failures_are_reported_after_candidate_evaluation_failure(self):
        with TemporaryDirectory() as tmp:
            src_path = Path(tmp) / "Example.java"
            original = "class Example { void a() {} }\n"
            candidate = "class Example { void a() { /* candidate */ } }\n"
            src_path.write_text(original, encoding="utf-8")
            remediation = self._build_remediation_for_apply(
                self.service, src_path, candidate, "org.example.Foo.doPost()",
                compile_result={"attempted": True, "success": True},
            )

            with patch.object(apply_flow_mod, "verify_candidate", side_effect=RuntimeError("candidate evaluation failed")):
                result = remediation.apply_fix(
                    "ISO-A.10-WEAK-HASH",
                    method_key=remediation.get_violation_context(None)["method_key"],
                    mode="apply",
                    max_attempts=1,
                )

            self.assertEqual(src_path.read_text(encoding="utf-8"), original)
            self.assertEqual(result["status"], "VERIFICATION_ERROR")
            self.assertIn("candidate evaluation failed", result["error"])
            self.assertEqual(result["verification"]["cleanup"], {"file_restored": None, "revision_published": None})


if __name__ == "__main__":
    unittest.main()
