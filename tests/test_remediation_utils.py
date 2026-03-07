import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

try:
    import javalang  # noqa: F401
except ImportError:  # pragma: no cover - environment guard
    javalang = None


def _structured_replace_method(method_code: str | list[str]) -> str:
    if isinstance(method_code, str):
        method_lines = method_code.splitlines()
    else:
        method_lines = method_code
    return json.dumps(
        {
            "decision": "replace_method",
            "replacement_method_lines": method_lines,
            "reason": "",
        }
    )


def _structured_no_fix(reason: str) -> str:
    return json.dumps(
        {
            "decision": "no_fix",
            "replacement_method_lines": [],
            "reason": reason,
        }
    )


@unittest.skipIf(javalang is None, "javalang not installed")
class RemediationUtilsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from codegraph.remediation import service

        cls.service = service

    def test_extract_json_block(self):
        text = 'Here is output:\n```json\n{"decision":"no_fix","replacement_method_lines":[],"reason":"x"}\n```'
        extracted = self.service._extract_json_block(text)
        self.assertEqual(extracted, '{"decision":"no_fix","replacement_method_lines":[],"reason":"x"}')

    def test_parse_structured_generation_replace_method(self):
        raw = _structured_replace_method('public void foo() { System.out.println("ok"); }')
        parsed = self.service.RemediationService._parse_structured_generation_response(raw, "com.example.Foo.foo()")
        self.assertTrue(parsed["raw_response_valid"])
        self.assertEqual(parsed["decision"], "replace_method")
        self.assertEqual(parsed["replacement_method_lines"], ['public void foo() { System.out.println("ok"); }'])
        self.assertIn('System.out.println("ok")', parsed["replacement_method_code"])
        self.assertEqual(parsed["reason"], "")
        self.assertIsNone(parsed["schema_error"])

    def test_parse_structured_generation_no_fix(self):
        raw = _structured_no_fix("safe minimal fix is not possible with the available context")
        parsed = self.service.RemediationService._parse_structured_generation_response(raw, "com.example.Foo.foo()")
        self.assertTrue(parsed["raw_response_valid"])
        self.assertEqual(parsed["decision"], "no_fix")
        self.assertEqual(parsed["reason"], "safe minimal fix is not possible with the available context")
        self.assertIsNone(parsed["replacement_method_code"])
        self.assertEqual(parsed["replacement_method_lines"], [])

    def test_parse_structured_generation_rejects_malformed_json(self):
        raw = '{"decision":"replace_method","replacement_method_lines":["public void foo() { }"]'
        parsed = self.service.RemediationService._parse_structured_generation_response(raw, "com.example.Foo.foo()")
        self.assertFalse(parsed["raw_response_valid"])
        self.assertTrue((parsed["schema_error"] or "").startswith("invalid_json"))

    def test_parse_structured_generation_rejects_missing_fields(self):
        raw = '{"decision":"replace_method","replacement_method_lines":["public void foo() { }"]}'
        parsed = self.service.RemediationService._parse_structured_generation_response(raw, "com.example.Foo.foo()")
        self.assertFalse(parsed["raw_response_valid"])
        self.assertIn("schema_mismatch", parsed["schema_error"])

    def test_parse_structured_generation_rejects_empty_replacement_lines(self):
        raw = _structured_replace_method([])
        parsed = self.service.RemediationService._parse_structured_generation_response(raw, "com.example.Foo.foo()")
        self.assertFalse(parsed["raw_response_valid"])
        self.assertEqual(parsed["schema_error"], "empty_replacement_lines")

    def test_parse_structured_generation_rejects_empty_no_fix_reason(self):
        raw = _structured_no_fix("   ")
        parsed = self.service.RemediationService._parse_structured_generation_response(raw, "com.example.Foo.foo()")
        self.assertFalse(parsed["raw_response_valid"])
        self.assertIn("no_fix requires reason", parsed["schema_error"])

    def test_parse_structured_generation_rejects_non_string_lines(self):
        raw = json.dumps(
            {
                "decision": "replace_method",
                "replacement_method_lines": ["public void foo() {", 123, "}"],
                "reason": "",
            }
        )
        parsed = self.service.RemediationService._parse_structured_generation_response(raw, "com.example.Foo.foo()")
        self.assertFalse(parsed["raw_response_valid"])
        self.assertIn("must contain strings", parsed["schema_error"])

    def test_parse_structured_generation_rejects_non_method_replacement(self):
        raw = _structured_replace_method('java.security.MessageDigest.getInstance("SHA-256");')
        parsed = self.service.RemediationService._parse_structured_generation_response(raw, "com.example.Foo.foo()")
        self.assertFalse(parsed["raw_response_valid"])
        self.assertEqual(parsed["schema_error"], "invalid_method_shape")

    def test_parse_structured_generation_normalizes_embedded_newlines_in_line_entries(self):
        raw = _structured_replace_method(
            ['@Override\\npublic void hash() {', '    System.out.println("ok");', '}']
        )
        parsed = self.service.RemediationService._parse_structured_generation_response(raw, "com.example.Foo.hash()")
        self.assertTrue(parsed["raw_response_valid"])
        self.assertIn("\npublic void hash()", parsed["replacement_method_code"])
        self.assertNotIn("\\n", parsed["replacement_method_code"])

    def test_parse_structured_generation_rejects_invalid_java_method_syntax(self):
        raw = _structured_replace_method(
            'public void hash() { System.out.println("oops"; }'
        )
        parsed = self.service.RemediationService._parse_structured_generation_response(raw, "com.example.Foo.hash()")
        self.assertFalse(parsed["raw_response_valid"])
        self.assertIn("invalid_java_syntax", parsed["schema_error"])

    def test_parse_structured_generation_rejects_method_name_mismatch(self):
        raw = _structured_replace_method("public void wrongName() { return; }")
        parsed = self.service.RemediationService._parse_structured_generation_response(raw, "com.example.Foo.hash()")
        self.assertFalse(parsed["raw_response_valid"])
        self.assertEqual(parsed["schema_error"], "method_name_mismatch")

    def test_parse_structured_generation_rejects_parameter_count_mismatch(self):
        raw = _structured_replace_method("public void hash(String a) { return; }")
        parsed = self.service.RemediationService._parse_structured_generation_response(
            raw,
            "com.example.Foo.hash(HttpServletRequest,HttpServletResponse)",
        )
        self.assertFalse(parsed["raw_response_valid"])
        self.assertEqual(parsed["schema_error"], "parameter_count_mismatch")

    def test_propose_full_method_uses_structured_generation_contract(self):
        svc_mod = self.service

        captured = {}

        def capture_llm(messages, **kwargs):
            captured["messages"] = messages
            captured["kwargs"] = kwargs
            return _structured_replace_method(
                "public void hash() { java.security.MessageDigest.getInstance(\"SHA-256\"); }"
            )

        remediation = svc_mod.RemediationService(llm_client=capture_llm)
        context = {
            "violation": {"violation_id": "ISO-A.10-WEAK-HASH", "reason": "md5"},
            "target_method": "com.example.Foo.hash()",
            "file_path": "Example.java",
            "rule_id": "ISO-A.10-WEAK-HASH",
            "evidence": {"source_code": "public void hash() { }", "graph_context": {}, "vector_context": []},
            "catalog_entry": {"title": "Cryptography (Weak Hash)"},
            "baseline_violations": [],
        }

        out = remediation.propose_full_method(context)
        self.assertEqual(out["decision"], "replace_method")
        self.assertTrue(out["generation"]["raw_response_valid"])
        self.assertEqual(captured["kwargs"]["response_format"]["type"], "json_schema")
        self.assertEqual(captured["kwargs"]["stop"], ["<|im_end|>", "<|endoftext|>"])
        self.assertIn("BEGIN_TASK_SPEC_JSON", captured["messages"][1]["content"])
        self.assertEqual(
            out["generation"]["replacement_method_lines"],
            ['public void hash() { java.security.MessageDigest.getInstance("SHA-256"); }'],
        )

    def test_remediation_prompt_omits_empty_graph_and_vector_blocks(self):
        from codegraph.remediation.prompting import RemediationPromptTemplate, RemediationTaskSpec

        prompt = RemediationPromptTemplate.build_user_prompt(
            context={
                "violation": {"violation_id": "ISO-A.10-WEAK-HASH", "reason": "md5"},
                "target_method": "com.example.Foo.hash()",
                "file_path": "Example.java",
                "rule_id": "ISO-A.10-WEAK-HASH",
                "evidence": {"source_code": "public void hash() {}", "graph_context": {}, "vector_context": []},
                "catalog_entry": {"title": "Cryptography (Weak Hash)"},
            },
            spec=RemediationTaskSpec(
                rule_id="ISO-A.10-WEAK-HASH",
                objective="Replace MD5 with SHA-256",
                allowed_transformations=[],
                non_goals=[],
            ),
        )

        self.assertNotIn(RemediationPromptTemplate.GRAPH_BEGIN, prompt)
        self.assertNotIn(RemediationPromptTemplate.VECTOR_BEGIN, prompt)

    def test_remediation_system_prompt_requires_complete_valid_method_or_no_fix(self):
        from codegraph.remediation.prompting import RemediationPromptTemplate

        prompt = RemediationPromptTemplate.system_prompt()
        self.assertIn("Only return replace_method when you can produce a COMPLETE syntactically valid Java method", prompt)
        self.assertIn("return no_fix instead of a partial draft", prompt)

    def test_remediation_capability_matches_supported_rule_set(self):
        from codegraph.remediation.capabilities import (
            DEFAULT_SUPPORTED_REMEDIATION_RULE_IDS,
            get_remediation_capability,
        )

        self.assertEqual(
            set(self.service.RemediationService._FIX_STRATEGIES.keys()),
            set(DEFAULT_SUPPORTED_REMEDIATION_RULE_IDS),
        )

        supported = get_remediation_capability(
            "ISO-A.10-WEAK-HASH",
            supported_rule_ids=self.service.RemediationService._FIX_STRATEGIES.keys(),
        )
        random_supported = get_remediation_capability(
            "ISO-A.10-WEAK-RANDOM",
            supported_rule_ids=self.service.RemediationService._FIX_STRATEGIES.keys(),
        )
        guarded = get_remediation_capability(
            "ISO-A.10-WEAK-CRYPTO",
            supported_rule_ids=self.service.RemediationService._FIX_STRATEGIES.keys(),
        )
        unsupported = get_remediation_capability(
            "ISO-A.9.4.1",
            supported_rule_ids=self.service.RemediationService._FIX_STRATEGIES.keys(),
        )

        self.assertTrue(supported.supported)
        self.assertEqual(supported.support_tier, "full")
        self.assertTrue(random_supported.supported)
        self.assertEqual(random_supported.support_tier, "full")
        self.assertTrue(guarded.supported)
        self.assertEqual(guarded.support_tier, "guarded")
        self.assertFalse(unsupported.supported)
        self.assertEqual(unsupported.support_tier, "manual")

    def test_preview_virtual_fix_rejects_unsupported_rule_without_llm_call(self):
        svc_mod = self.service

        llm_client = Mock(return_value=_structured_replace_method("public void noop() { return; }"))
        remediation = svc_mod.RemediationService(llm_client=llm_client)
        remediation.get_violation_context = lambda *_args, **_kwargs: {  # type: ignore[method-assign]
            "violation": {"violation_id": "ISO-A.12.4.1", "reason": "logging"},
            "target_method": "com.example.Foo.update()",
            "file_path": "Example.java",
            "rule_id": "ISO-A.12.4.1",
            "evidence": {"source_code": "", "graph_context": {}, "vector_context": []},
            "catalog_entry": {"title": "Event Logging"},
            "baseline_violations": [],
        }

        out = remediation.preview_virtual_fix("ISO-A.12.4.1")
        self.assertEqual(out.get("status"), "INVALID")
        self.assertEqual(out.get("error"), "unsupported_rule_for_auto_fix")
        llm_client.assert_not_called()

    def test_preview_virtual_fix_returns_no_fix_for_preflight_random_shape(self):
        svc_mod = self.service

        llm_client = Mock(return_value=_structured_replace_method("public void noop() { return; }"))
        remediation = svc_mod.RemediationService(llm_client=llm_client)
        remediation.get_violation_context = lambda *_args, **_kwargs: {  # type: ignore[method-assign]
            "violation": {"violation_id": "ISO-A.10-WEAK-RANDOM", "reason": "rng"},
            "target_method": "com.example.Foo.random()",
            "file_path": "Example.java",
            "rule_id": "ISO-A.10-WEAK-RANDOM",
            "evidence": {"source_code": "public void random() { UUID.randomUUID(); }", "graph_context": {}, "vector_context": []},
            "catalog_entry": {"title": "Cryptography (Insecure Randomness)"},
            "baseline_violations": [],
        }

        out = remediation.preview_virtual_fix("ISO-A.10-WEAK-RANDOM")
        self.assertEqual(out.get("status"), "NO_FIX")
        self.assertEqual(out["generation"]["decision"], "no_fix")
        self.assertEqual(out["generation"]["replacement_method_lines"], None)
        llm_client.assert_not_called()

    def test_preview_virtual_fix_allows_supported_random_shape(self):
        svc_mod = self.service

        llm_client = Mock(
            return_value=_structured_replace_method(
                "public void random() { new java.security.SecureRandom().nextInt(); }"
            )
        )
        remediation = svc_mod.RemediationService(llm_client=llm_client)
        remediation.get_violation_context = lambda *_args, **_kwargs: {  # type: ignore[method-assign]
            "violation": {"violation_id": "ISO-A.10-WEAK-RANDOM", "reason": "rng"},
            "target_method": "com.example.Foo.random()",
            "file_path": "Example.java",
            "rule_id": "ISO-A.10-WEAK-RANDOM",
            "evidence": {
                "source_code": "public void random() { new java.util.Random().nextInt(); }",
                "graph_context": {},
                "vector_context": [],
            },
            "catalog_entry": {"title": "Cryptography (Insecure Randomness)"},
            "baseline_violations": [],
        }

        with patch.object(svc_mod, "evaluate_bundle", return_value=[]):
            out = remediation.preview_virtual_fix("ISO-A.10-WEAK-RANDOM")

        self.assertEqual(out.get("status"), "OK")
        self.assertEqual(out.get("opa_status"), "PASS")
        self.assertEqual(out["generation"]["decision"], "replace_method")
        self.assertIsInstance(out["generation"]["replacement_method_lines"], list)
        llm_client.assert_called_once()

    def test_preview_virtual_fix_allows_guarded_crypto_literal_subcase(self):
        svc_mod = self.service

        llm_client = Mock(
            return_value=_structured_replace_method(
                'public void encrypt() { Cipher.getInstance("AES/GCM/NoPadding"); }'
            )
        )
        remediation = svc_mod.RemediationService(llm_client=llm_client)
        remediation.get_violation_context = lambda *_args, **_kwargs: {  # type: ignore[method-assign]
            "violation": {"violation_id": "ISO-A.10-WEAK-CRYPTO", "reason": "crypto"},
            "target_method": "com.example.Foo.encrypt()",
            "file_path": "Example.java",
            "rule_id": "ISO-A.10-WEAK-CRYPTO",
            "evidence": {
                "source_code": 'public void encrypt() { Cipher.getInstance("DESede/ECB/PKCS5Padding"); }',
                "graph_context": {},
                "vector_context": [],
            },
            "catalog_entry": {"title": "Cryptography (Weak Cipher)"},
            "baseline_violations": [],
        }

        with patch.object(svc_mod, "evaluate_bundle", return_value=[]):
            out = remediation.preview_virtual_fix("ISO-A.10-WEAK-CRYPTO")

        self.assertEqual(out.get("status"), "OK")
        self.assertEqual(out["generation"]["decision"], "replace_method")
        llm_client.assert_called_once()

    def test_preview_virtual_fix_allows_structured_no_fix_from_model(self):
        svc_mod = self.service

        llm_client = Mock(return_value=_structured_no_fix("changing this cipher safely needs broader protocol context"))
        remediation = svc_mod.RemediationService(llm_client=llm_client)
        remediation.get_violation_context = lambda *_args, **_kwargs: {  # type: ignore[method-assign]
            "violation": {"violation_id": "ISO-A.10-WEAK-CRYPTO", "reason": "crypto"},
            "target_method": "com.example.Foo.encrypt()",
            "file_path": "Example.java",
            "rule_id": "ISO-A.10-WEAK-CRYPTO",
            "evidence": {
                "source_code": 'public void encrypt() { Cipher.getInstance("DESede/ECB/PKCS5Padding"); }',
                "graph_context": {},
                "vector_context": [],
            },
            "catalog_entry": {"title": "Cryptography (Weak Cipher)"},
            "baseline_violations": [],
        }

        out = remediation.preview_virtual_fix("ISO-A.10-WEAK-CRYPTO")
        self.assertEqual(out.get("status"), "NO_FIX")
        self.assertEqual(out["generation"]["decision"], "no_fix")
        self.assertIn("broader protocol context", out["generation"]["reason"])

    def test_preview_virtual_fix_returns_generation_error_for_invalid_structured_output(self):
        svc_mod = self.service

        llm_client = Mock(return_value='{"decision":"replace_method","replacement_method_lines":["oops"],"reason":""}')
        remediation = svc_mod.RemediationService(llm_client=llm_client)
        remediation.get_violation_context = lambda *_args, **_kwargs: {  # type: ignore[method-assign]
            "violation": {"violation_id": "ISO-A.10-WEAK-HASH", "reason": "md5"},
            "target_method": "com.example.Foo.hash()",
            "file_path": "Example.java",
            "rule_id": "ISO-A.10-WEAK-HASH",
            "evidence": {"source_code": "public void hash() { }", "graph_context": {}, "vector_context": []},
            "catalog_entry": {"title": "Cryptography (Weak Hash)"},
            "baseline_violations": [],
        }

        out = remediation.preview_virtual_fix("ISO-A.10-WEAK-HASH")
        self.assertEqual(out.get("status"), "GENERATION_ERROR")
        self.assertFalse(out["generation"]["raw_response_valid"])
        self.assertIn("invalid_method_shape", out["error"])

    def test_apply_fix_returns_generation_error_for_invalid_structured_output(self):
        svc_mod = self.service
        with TemporaryDirectory() as tmp:
            src_path = Path(tmp) / "Example.java"
            src_path.write_text("class Example { void hash() {} }\n", encoding="utf-8")

            remediation = svc_mod.RemediationService(llm_client=lambda *_args, **_kwargs: "")
            remediation.get_violation_context = lambda *_args, **_kwargs: {  # type: ignore[method-assign]
                "violation": {"violation_id": "ISO-A.10-WEAK-HASH", "reason": "md5"},
                "target_method": "com.example.Foo.hash()",
                "file_path": src_path.as_posix(),
                "rule_id": "ISO-A.10-WEAK-HASH",
                "evidence": {"source_code": "public void hash() { }", "graph_context": {}, "vector_context": []},
                "catalog_entry": {"title": "Cryptography (Weak Hash)"},
                "baseline_violations": [],
            }
            remediation._resolve_file_path = lambda *_args, **_kwargs: src_path  # type: ignore[method-assign]
            remediation.propose_full_method = (  # type: ignore[method-assign]
                lambda *_args, **_kwargs: {
                    "decision": "replace_method",
                    "replacement_method_lines": None,
                    "replacement_method_code": None,
                    "reason": "",
                    "schema_error": "invalid_java_syntax: expected \")\"",
                    "generation": {
                        "decision": "replace_method",
                        "replacement_method_lines": None,
                        "replacement_method_code": None,
                        "reason": "",
                        "raw_response_valid": False,
                        "schema_error": "invalid_java_syntax: expected \")\"",
                    },
                    "raw_output": '{"decision":"replace_method"}',
                }
            )

            out = remediation.apply_fix(
                "ISO-A.10-WEAK-HASH",
                target_method="com.example.Foo.hash()",
                file_path=src_path.as_posix(),
                mode="dry_run",
                max_attempts=1,
            )
            self.assertEqual(out.get("status"), "GENERATION_ERROR")
            self.assertIn("invalid_java_syntax", out.get("error", ""))

    def test_apply_fix_restores_original_file_on_verification_exception(self):
        svc_mod = self.service

        with TemporaryDirectory() as tmp:
            src_path = Path(tmp) / "Example.java"
            original_content = "class Example { void a() {} }\n"
            src_path.write_text(original_content, encoding="utf-8")

            target_method = (
                "org.owasp.benchmark.testcode.BenchmarkTest00272.doPost(HttpServletRequest,HttpServletResponse)"
            )

            remediation = svc_mod.RemediationService(llm_client=lambda *_args, **_kwargs: "")
            remediation.get_violation_context = lambda *_args, **_kwargs: {  # type: ignore[method-assign]
                "violation": {"violation_id": "ISO-A.10-WEAK-HASH", "reason": "md5"},
                "target_method": target_method,
                "file_path": src_path.as_posix(),
                "rule_id": "ISO-A.10-WEAK-HASH",
                "evidence": {
                    "source_code": 'public void doPost(...) { MessageDigest.getInstance("MD5"); }',
                    "graph_context": {},
                    "vector_context": [],
                },
                "catalog_entry": {"title": "Cryptography (Weak Hash)"},
                "baseline_violations": [],
            }
            remediation._resolve_file_path = lambda *_args, **_kwargs: src_path  # type: ignore[method-assign]
            remediation.propose_full_method = (  # type: ignore[method-assign]
                lambda *_args, **_kwargs: {
                    "decision": "replace_method",
                    "replacement_method_lines": ["public void doPost(...) { /* sha-256 */ }"],
                    "replacement_method_code": "public void doPost(...) { /* sha-256 */ }",
                    "reason": None,
                    "schema_error": None,
                    "generation": {
                        "decision": "replace_method",
                        "replacement_method_lines": ["public void doPost(...) { /* sha-256 */ }"],
                        "replacement_method_code": "public void doPost(...) { /* sha-256 */ }",
                        "reason": "",
                        "raw_response_valid": True,
                        "schema_error": None,
                    },
                    "raw_output": None,
                }
            )
            remediation._replace_method_in_source = (  # type: ignore[method-assign]
                lambda *_args, **_kwargs: (
                    "class Example { void a() { /* UPDATED */ } }\n",
                    "void a() {}",
                    "void a() { /* UPDATED */ }",
                )
            )
            remediation._prepare_temp_workspace = (  # type: ignore[method-assign]
                lambda tmp_root, _resolved: (
                    tmp_root,
                    Path(tmp_root) / "Example.java",
                    Path(tmp_root),
                )
            )
            remediation._compile_project = (  # type: ignore[method-assign]
                lambda *_args, **_kwargs: {
                    "attempted": False,
                    "success": False,
                    "output_snippet": None,
                    "skipped_reason": "test",
                }
            )

            orig_psfc = svc_mod.process_single_file_content
            orig_policy_evaluator = svc_mod.PolicyEvaluator

            class BoomPolicyEvaluator:
                def evaluate(self, _method_signature: str):
                    raise RuntimeError("boom")

            try:
                svc_mod.process_single_file_content = lambda *_args, **_kwargs: None
                svc_mod.PolicyEvaluator = BoomPolicyEvaluator  # type: ignore[assignment]

                out = remediation.apply_fix(
                    "ISO-A.10-WEAK-HASH",
                    target_method=target_method,
                    file_path=src_path.as_posix(),
                    mode="dry_run",
                    max_attempts=1,
                )
                self.assertEqual(out.get("status"), "VERIFICATION_ERROR")
                self.assertEqual(src_path.read_text(encoding="utf-8"), original_content)
            finally:
                svc_mod.process_single_file_content = orig_psfc
                svc_mod.PolicyEvaluator = orig_policy_evaluator

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


if __name__ == "__main__":
    unittest.main()
