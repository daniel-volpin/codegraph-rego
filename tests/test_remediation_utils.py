import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

try:
    import javalang  # noqa: F401
except ImportError:  # pragma: no cover - environment guard
    javalang = None


@unittest.skipIf(javalang is None, "javalang not installed")
class RemediationUtilsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from codegraph.remediation import service

        cls.service = service

    def test_extract_json_block(self):
        text = 'Here is output:\n```json\n{"updated_source_code": "ok"}\n```'
        extracted = self.service._extract_json_block(text)
        self.assertEqual(extracted, '{"updated_source_code": "ok"}')

    def test_parse_llm_virtual_json(self):
        raw = 'note\n{"updated_source_code": "public void foo() {}", "explanation": "ok"}'
        parsed = self.service.RemediationService._parse_llm_virtual_json(raw)
        self.assertEqual(parsed["updated_source_code"], "public void foo() {}")
        self.assertEqual(parsed["explanation"], "ok")

    def test_parse_llm_virtual_json_sample_payload(self):
        raw = (
            '{"updated_source_code":"public void doPost(HttpServletRequest request, '
            "HttpServletResponse response) {"
            'java.security.MessageDigest md = java.security.MessageDigest.getInstance(\\"SHA-256\\");'
            '}","explanation":"Switched weak hash to SHA-256."}'
        )
        parsed = self.service.RemediationService._parse_llm_virtual_json(raw)
        self.assertIsNone(parsed.get("parse_error"))
        self.assertGreater(len(parsed["updated_source_code"]), 0)
        self.assertEqual(parsed["explanation"], "Switched weak hash to SHA-256.")

    def test_parse_llm_virtual_json_replacement_method_code(self):
        raw = (
            '{"file_path":"Example.java","target_method_signature":"example.Foo.doPost(HttpServletRequest,HttpServletResponse)",'
            '"replacement_method_code":"public void doPost(HttpServletRequest request, HttpServletResponse response) {\\n'
            'java.security.MessageDigest md = java.security.MessageDigest.getInstance(\\"SHA-256\\");\\n}",'
            '"explanation":"Structured output patch."}'
        )
        parsed = self.service.RemediationService._parse_llm_virtual_json(raw)
        self.assertIsNone(parsed.get("parse_error"))
        self.assertIn("SHA-256", parsed["updated_source_code"])

    def test_capture_raw_llm_output_on_invalid_json(self):
        invalid_raw = '{"updated_source_code":"public void foo() {}"'
        parsed = self.service.RemediationService._parse_llm_virtual_json(invalid_raw)
        self.assertTrue((parsed.get("parse_error") or "").startswith("invalid_json"))
        with TemporaryDirectory() as tmp:
            out = self.service._capture_raw_llm_output(tmp, "BenchmarkTest99999", 1, invalid_raw)
            self.assertIsNotNone(out)
            self.assertTrue(Path(out).is_file())
            self.assertEqual(Path(out).read_text(encoding="utf-8"), invalid_raw)

    def test_parse_llm_virtual_json_rejects_unescaped_quotes_in_code(self):
        # This mimics the real failure mode in remediation_eval: the model returns JSON-like text,
        # but embeds raw `"` from Java string literals inside a JSON string field.
        raw = (
            '{"file_path":"Example.java","target_method_signature":"x.y.Foo.doPost(A,B)",'
            '"replacement_method_code":"public void doPost(A a, B b) { System.out.println("hi"); }"}'
        )
        parsed = self.service.RemediationService._parse_llm_virtual_json(raw)
        self.assertTrue((parsed.get("parse_error") or "").startswith("invalid_json"))

    def test_parse_llm_virtual_json_accepts_code_only_output(self):
        raw = "public void doPost(A a, B b) { return; }"
        parsed = self.service.RemediationService._parse_llm_virtual_json(raw)
        self.assertIsNone(parsed.get("parse_error"))
        self.assertEqual(parsed["updated_source_code"], raw)

    def test_parse_llm_virtual_json_accepts_fenced_code_block(self):
        raw = "```java\npublic void doPost(A a, B b) { return; }\n```"
        parsed = self.service.RemediationService._parse_llm_virtual_json(raw)
        self.assertIsNone(parsed.get("parse_error"))
        self.assertIn("public void doPost", parsed["updated_source_code"])

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
        sql_manual = get_remediation_capability(
            "ISO-A.8-SQL-INJECTION",
            supported_rule_ids=self.service.RemediationService._FIX_STRATEGIES.keys(),
        )
        path_manual = get_remediation_capability(
            "ISO-A.8-PATH-TRAVERSAL",
            supported_rule_ids=self.service.RemediationService._FIX_STRATEGIES.keys(),
        )

        self.assertTrue(supported.supported)
        self.assertEqual(supported.support_tier, "full")
        self.assertEqual(supported.reason_code, "supported_rule_for_auto_fix")
        self.assertTrue(random_supported.supported)
        self.assertEqual(random_supported.support_tier, "full")
        self.assertTrue(random_supported.safe_refusal_possible)
        self.assertTrue(guarded.supported)
        self.assertEqual(guarded.support_tier, "guarded")
        self.assertTrue(guarded.safe_refusal_possible)
        self.assertFalse(unsupported.supported)
        self.assertEqual(unsupported.support_tier, "manual")
        self.assertEqual(unsupported.reason_code, "unsupported_rule_for_auto_fix")
        self.assertIn("cross-layer parameterization", sql_manual.rationale)
        self.assertIn("path policy", path_manual.rationale)

    def test_preview_virtual_fix_rejects_unsupported_rule_without_llm_call(self):
        svc_mod = self.service

        llm_client = Mock(return_value="public void noop() { return; }")
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

    def test_apply_fix_rejects_unsupported_rule_without_llm_call(self):
        svc_mod = self.service

        llm_client = Mock(return_value="public void noop() { return; }")
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

        out = remediation.apply_fix("ISO-A.12.4.1", mode="dry_run", max_attempts=1)
        self.assertEqual(out.get("status"), "INVALID")
        self.assertEqual(out.get("error"), "unsupported_rule_for_auto_fix")
        llm_client.assert_not_called()

    def test_prompt_template_system_is_rule_agnostic_and_task_spec_is_structured_json(self):
        svc_mod = self.service

        captured = []

        def capture_llm(messages, *_args, **_kwargs):
            captured.append(messages)
            return "public void hash() { return; }"

        remediation = svc_mod.RemediationService(llm_client=capture_llm)
        base_context = {
            "violation": {"violation_id": "X", "reason": "test"},
            "target_method": "com.example.Foo.hash()",
            "file_path": "Example.java",
            "evidence": {"source_code": "public void hash() { }", "graph_context": {}, "vector_context": []},
            "catalog_entry": {"title": "Test"},
            "baseline_violations": [],
        }

        out_hash = remediation.propose_full_method({**base_context, "rule_id": "ISO-A.10-WEAK-HASH"})
        self.assertIsNone(out_hash.get("parse_error"))
        out_crypto = remediation.propose_full_method({**base_context, "rule_id": "ISO-A.10-WEAK-CRYPTO"})
        self.assertIsNone(out_crypto.get("parse_error"))

        self.assertEqual(len(captured), 2)
        system_1 = captured[0][0]["content"]
        system_2 = captured[1][0]["content"]
        self.assertEqual(system_1, system_2)

        upper = system_1.upper()
        for needle in ["MD5", "SHA", "SHA-256", "DES", "RC4", "ECB"]:
            self.assertNotIn(needle, upper)

        user_1 = captured[0][1]["content"]
        user_2 = captured[1][1]["content"]
        self.assertIn("BEGIN_TASK_SPEC_JSON", user_1)
        self.assertIn("END_TASK_SPEC_JSON", user_1)
        self.assertIn('"rule_id": "ISO-A.10-WEAK-HASH"', user_1)
        self.assertIn("BEGIN_TASK_SPEC_JSON", user_2)
        self.assertIn("END_TASK_SPEC_JSON", user_2)
        self.assertIn('"rule_id": "ISO-A.10-WEAK-CRYPTO"', user_2)

    def test_no_fix_output_is_handled(self):
        svc_mod = self.service

        remediation = svc_mod.RemediationService(
            llm_client=lambda *_args, **_kwargs: "NO_FIX: cannot safely update without build context"
        )
        remediation.get_violation_context = lambda *_args, **_kwargs: {  # type: ignore[method-assign]
            "violation": {"violation_id": "ISO-A.10-WEAK-HASH", "reason": "md5"},
            "target_method": "com.example.Foo.hash()",
            "file_path": "Example.java",
            "rule_id": "ISO-A.10-WEAK-HASH",
            "evidence": {"source_code": "public void hash() {}", "graph_context": {}, "vector_context": []},
            "catalog_entry": {"title": "Cryptography (Weak Hash)"},
            "baseline_violations": [],
        }

        out = remediation.preview_virtual_fix("ISO-A.10-WEAK-HASH")
        self.assertEqual(out.get("status"), "FAIL")
        self.assertTrue(str(out.get("error") or "").startswith("NO_FIX:"))

    def test_preview_virtual_fix_preflights_unsupported_random_shape_without_llm_call(self):
        svc_mod = self.service

        llm_client = Mock(return_value="public void noop() { return; }")
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
        self.assertEqual(out.get("status"), "FAIL")
        self.assertTrue(str(out.get("error") or "").startswith("NO_FIX:"))
        llm_client.assert_not_called()

    def test_preview_virtual_fix_preflights_unsupported_crypto_shape_without_llm_call(self):
        svc_mod = self.service

        llm_client = Mock(return_value="public void noop() { return; }")
        remediation = svc_mod.RemediationService(llm_client=llm_client)
        remediation.get_violation_context = lambda *_args, **_kwargs: {  # type: ignore[method-assign]
            "violation": {"violation_id": "ISO-A.10-WEAK-CRYPTO", "reason": "crypto"},
            "target_method": "com.example.Foo.encrypt()",
            "file_path": "Example.java",
            "rule_id": "ISO-A.10-WEAK-CRYPTO",
            "evidence": {"source_code": 'public void encrypt() { Cipher.getInstance(algorithm); }', "graph_context": {}, "vector_context": []},
            "catalog_entry": {"title": "Cryptography (Weak Cipher)"},
            "baseline_violations": [],
        }

        out = remediation.preview_virtual_fix("ISO-A.10-WEAK-CRYPTO")
        self.assertEqual(out.get("status"), "FAIL")
        self.assertTrue(str(out.get("error") or "").startswith("NO_FIX:"))
        llm_client.assert_not_called()

    def test_preview_virtual_fix_allows_supported_random_shape(self):
        svc_mod = self.service

        llm_client = Mock(return_value="public void random() { new java.security.SecureRandom().nextInt(); }")
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
        llm_client.assert_called_once()

    def test_preview_virtual_fix_allows_guarded_crypto_literal_subcase(self):
        svc_mod = self.service

        llm_client = Mock(return_value='public void encrypt() { Cipher.getInstance("AES/GCM/NoPadding"); }')
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
        self.assertEqual(out.get("opa_status"), "PASS")
        llm_client.assert_called_once()

    def test_apply_fix_restores_original_file_on_verification_exception(self):
        # Ensure dry_run restores the on-disk file even if verification (PolicyEvaluator) blows up.
        from tempfile import TemporaryDirectory

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
                    "updated_source_code": "public void doPost(...) { /* sha-256 */ }",
                    "explanation": None,
                    "parse_error": None,
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
                self.assertEqual(out.get("status"), "ERROR")
                self.assertEqual(src_path.read_text(encoding="utf-8"), original_content)
            finally:
                svc_mod.process_single_file_content = orig_psfc
                svc_mod.PolicyEvaluator = orig_policy_evaluator

    def test_unified_diff(self):
        diff = self.service._unified_diff("a\nb", "a\nc", label="method")
        self.assertIn("-b", diff)
        self.assertIn("+c", diff)


if __name__ == "__main__":
    unittest.main()
