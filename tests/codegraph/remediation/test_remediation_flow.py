import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from tests.codegraph.remediation._test_helpers import RemediationTestBase, _structured_apply_edits, _structured_no_fix


class RemediationFlowTests(RemediationTestBase):
    def test_propose_method_edits_uses_structured_generation_contract(self):
        svc_mod = self.service

        captured = {}

        def capture_llm(messages, **kwargs):
            captured["messages"] = messages
            captured["kwargs"] = kwargs
            return _structured_apply_edits(
                original_method='public void hash() { java.security.MessageDigest.getInstance("MD5"); }',
                replacement_method='public void hash() { java.security.MessageDigest.getInstance("SHA-256"); }',
            )

        remediation = svc_mod.RemediationService(llm_client=capture_llm)
        exact_method_source = 'public void hash() { java.security.MessageDigest.getInstance("MD5"); }'
        context = {
            "violation": {"violation_id": "ISO-A.10-WEAK-HASH", "reason": "md5"},
            "target_method": "com.example.Foo.hash()",
            "file_path": "Example.java",
            "rule_id": "ISO-A.10-WEAK-HASH",
            "evidence": {"source_code": exact_method_source, "graph_context": {}, "vector_context": []},
            "catalog_entry": {"title": "Cryptography (Weak Hash)"},
            "baseline_violations": [],
            "exact_method_source": exact_method_source,
            "numbered_method_source": '1: public void hash() { java.security.MessageDigest.getInstance("MD5"); }',
            "remediation_plan": svc_mod.build_remediation_plan(exact_method_source),
        }

        out = remediation.propose_method_edits(context)
        self.assertEqual(out["decision"], "apply_edits")
        self.assertTrue(out["generation"]["raw_response_valid"])
        self.assertEqual(captured["kwargs"]["response_format"]["type"], "json_schema")
        self.assertEqual(captured["kwargs"]["stop"], ["<|im_end|>", "<|endoftext|>"])
        self.assertIn("BEGIN_TASK_SPEC_JSON", captured["messages"][1]["content"])
        self.assertIn("BEGIN_REMEDIATION_PLAN_JSON", captured["messages"][1]["content"])
        self.assertIn("BEGIN_NUMBERED_METHOD_SNIPPET", captured["messages"][1]["content"])
        self.assertEqual(out["generation"]["edits"][0]["start_line"], 1)

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
        self.assertIn("Return only the changed spans as edits", prompt)
        self.assertIn("If you cannot produce a safe minimal edit plan, return no_fix", prompt)
        self.assertIn("If the plan lists terminal invocation contracts", prompt)

    def test_compile_project_honors_explicit_build_command(self):
        with TemporaryDirectory() as tmp:
            build_root = Path(tmp)
            (build_root / "pom.xml").write_text("<project/>", encoding="utf-8")
            with patch.object(self.service.subprocess, "run") as run_mock:
                run_mock.return_value = Mock(returncode=0, stdout="", stderr="")
                result = self.service.RemediationService._compile_project(
                    build_root,
                    build_command="mvn -q -DskipTests -Dspotless.skip=true compile",
                )

        self.assertTrue(result["attempted"])
        self.assertTrue(result["success"])
        run_mock.assert_called_once()
        self.assertEqual(
            run_mock.call_args.args[0],
            ["mvn", "-q", "-DskipTests", "-Dspotless.skip=true", "compile"],
        )

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

        llm_client = Mock(
            return_value=_structured_apply_edits(
                original_method="public void noop() { return; }",
                replacement_method="public void noop() { return; }",
            )
        )
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

        llm_client = Mock(
            return_value=_structured_apply_edits(
                original_method="public void noop() { return; }",
                replacement_method="public void noop() { return; }",
            )
        )
        remediation = svc_mod.RemediationService(llm_client=llm_client)
        original_method = "public void random() { UUID.randomUUID(); }"
        remediation.get_violation_context = lambda *_args, **_kwargs: {  # type: ignore[method-assign]
            "violation": {"violation_id": "ISO-A.10-WEAK-RANDOM", "reason": "rng"},
            "target_method": "com.example.Foo.random()",
            "file_path": "Example.java",
            "rule_id": "ISO-A.10-WEAK-RANDOM",
            "evidence": {"source_code": original_method, "graph_context": {}, "vector_context": []},
            "catalog_entry": {"title": "Cryptography (Insecure Randomness)"},
            "baseline_violations": [],
            "exact_method_source": original_method,
        }

        out = remediation.preview_virtual_fix("ISO-A.10-WEAK-RANDOM")
        self.assertEqual(out.get("status"), "NO_FIX")
        self.assertEqual(out["generation"]["decision"], "no_fix")
        self.assertEqual(out["generation"]["replacement_method_lines"], None)
        llm_client.assert_not_called()

    def test_preview_virtual_fix_allows_supported_random_shape(self):
        svc_mod = self.service

        original_method = "public void random() { new java.util.Random().nextInt(); }"
        llm_client = Mock(
            return_value=_structured_apply_edits(
                original_method=original_method,
                replacement_method="public void random() { new java.security.SecureRandom().nextInt(); }",
            )
        )
        remediation = svc_mod.RemediationService(llm_client=llm_client)
        remediation.get_violation_context = lambda *_args, **_kwargs: {  # type: ignore[method-assign]
            "violation": {"violation_id": "ISO-A.10-WEAK-RANDOM", "reason": "rng"},
            "target_method": "com.example.Foo.random()",
            "file_path": "Example.java",
            "rule_id": "ISO-A.10-WEAK-RANDOM",
            "evidence": {
                "source_code": original_method,
                "graph_context": {},
                "vector_context": [],
            },
            "catalog_entry": {"title": "Cryptography (Insecure Randomness)"},
            "baseline_violations": [],
            "exact_method_source": original_method,
        }

        with patch.object(svc_mod, "evaluate_bundle", return_value=[]):
            out = remediation.preview_virtual_fix("ISO-A.10-WEAK-RANDOM")

        self.assertEqual(out.get("status"), "OK")
        self.assertEqual(out.get("opa_status"), "PASS")
        self.assertEqual(out["generation"]["decision"], "apply_edits")
        self.assertIsInstance(out["generation"]["replacement_method_lines"], list)
        llm_client.assert_called_once()

    def test_preview_virtual_fix_allows_guarded_crypto_literal_subcase(self):
        svc_mod = self.service

        original_method = 'public void encrypt() { Cipher.getInstance("DESede/ECB/PKCS5Padding"); }'
        llm_client = Mock(
            return_value=_structured_apply_edits(
                original_method=original_method,
                replacement_method='public void encrypt() { Cipher.getInstance("AES/GCM/NoPadding"); }',
            )
        )
        remediation = svc_mod.RemediationService(llm_client=llm_client)
        remediation.get_violation_context = lambda *_args, **_kwargs: {  # type: ignore[method-assign]
            "violation": {"violation_id": "ISO-A.10-WEAK-CRYPTO", "reason": "crypto"},
            "target_method": "com.example.Foo.encrypt()",
            "file_path": "Example.java",
            "rule_id": "ISO-A.10-WEAK-CRYPTO",
            "evidence": {
                "source_code": original_method,
                "graph_context": {},
                "vector_context": [],
            },
            "catalog_entry": {"title": "Cryptography (Weak Cipher)"},
            "baseline_violations": [],
            "exact_method_source": original_method,
        }

        with patch.object(svc_mod, "evaluate_bundle", return_value=[]):
            out = remediation.preview_virtual_fix("ISO-A.10-WEAK-CRYPTO")

        self.assertEqual(out.get("status"), "OK")
        self.assertEqual(out["generation"]["decision"], "apply_edits")
        llm_client.assert_called_once()

    def test_preflight_crypto_uses_exact_method_when_evidence_is_literal_stripped(self):
        svc_mod = self.service

        exact_method = 'public void encrypt() { Cipher.getInstance("DES/CBC/PKCS5Padding"); }'
        stripped_evidence = 'public void encrypt() { Cipher.getInstance(""); }'
        context = {
            "rule_id": "ISO-A.10-WEAK-CRYPTO",
            "evidence": {"source_code": stripped_evidence, "graph_context": {}, "vector_context": []},
            "exact_method_source": exact_method,
        }

        self.assertIsNone(svc_mod.RemediationService._preflight_fixability_reason(context))

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

        llm_client = Mock(
            return_value='{"decision":"apply_edits","edits":[{"start_line":1,"end_line":1,"original_lines":["public void hash() { }"],"replacement_lines":["oops"]}],"reason":""}'
        )
        remediation = svc_mod.RemediationService(llm_client=llm_client)
        original_method = "public void hash() { }"
        remediation.get_violation_context = lambda *_args, **_kwargs: {  # type: ignore[method-assign]
            "violation": {"violation_id": "ISO-A.10-WEAK-HASH", "reason": "md5"},
            "target_method": "com.example.Foo.hash()",
            "file_path": "Example.java",
            "rule_id": "ISO-A.10-WEAK-HASH",
            "evidence": {"source_code": original_method, "graph_context": {}, "vector_context": []},
            "catalog_entry": {"title": "Cryptography (Weak Hash)"},
            "baseline_violations": [],
            "exact_method_source": original_method,
        }

        out = remediation.preview_virtual_fix("ISO-A.10-WEAK-HASH")
        self.assertEqual(out.get("status"), "GENERATION_ERROR")
        self.assertFalse(out["generation"]["raw_response_valid"])
        self.assertIn("invalid_java_syntax", out["error"])


if __name__ == "__main__":
    unittest.main()
