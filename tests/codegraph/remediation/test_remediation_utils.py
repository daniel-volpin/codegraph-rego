import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

try:
    import javalang  # noqa: F401
except ImportError:  # pragma: no cover - environment guard
    javalang = None


def _structured_apply_edits(
    *,
    original_method: str | list[str],
    replacement_method: str | list[str],
    start_line: int = 1,
    end_line: int | None = None,
) -> str:
    original_lines = original_method.splitlines() if isinstance(original_method, str) else list(original_method)
    replacement_lines = replacement_method.splitlines() if isinstance(replacement_method, str) else list(replacement_method)
    if end_line is None:
        end_line = start_line + len(original_lines) - 1
    return json.dumps(
        {
            "decision": "apply_edits",
            "edits": [
                {
                    "start_line": start_line,
                    "end_line": end_line,
                    "original_lines": original_lines,
                    "replacement_lines": replacement_lines,
                }
            ],
            "reason": "",
        }
    )


def _structured_no_fix(reason: str) -> str:
    return json.dumps(
        {
            "decision": "no_fix",
            "edits": [],
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
        text = 'Here is output:\n```json\n{"decision":"no_fix","edits":[],"reason":"x"}\n```'
        extracted = self.service._extract_json_block(text)
        self.assertEqual(extracted, '{"decision":"no_fix","edits":[],"reason":"x"}')

    def test_parse_structured_generation_apply_edits(self):
        original = 'public void foo() { System.out.println("old"); }'
        replacement = 'public void foo() { System.out.println("ok"); }'
        raw = _structured_apply_edits(original_method=original, replacement_method=replacement)
        parsed = self.service.RemediationService._parse_structured_generation_response(
            raw,
            target_method="com.example.Foo.foo()",
            original_method_lines=original.splitlines(),
        )
        self.assertTrue(parsed["raw_response_valid"])
        self.assertEqual(parsed["decision"], "apply_edits")
        self.assertEqual(parsed["edits"][0]["start_line"], 1)
        self.assertEqual(parsed["replacement_method_lines"], [replacement])
        self.assertIn('System.out.println("ok")', parsed["replacement_method_code"])
        self.assertEqual(parsed["reason"], "")
        self.assertIsNone(parsed["schema_error"])

    def test_parse_structured_generation_no_fix(self):
        raw = _structured_no_fix("safe minimal fix is not possible with the available context")
        parsed = self.service.RemediationService._parse_structured_generation_response(
            raw,
            target_method="com.example.Foo.foo()",
            original_method_lines=["public void foo() {}"],
        )
        self.assertTrue(parsed["raw_response_valid"])
        self.assertEqual(parsed["decision"], "no_fix")
        self.assertEqual(parsed["reason"], "safe minimal fix is not possible with the available context")
        self.assertIsNone(parsed["replacement_method_code"])
        self.assertEqual(parsed["edits"], [])

    def test_parse_structured_generation_rejects_malformed_json(self):
        raw = '{"decision":"apply_edits","edits":[]'
        parsed = self.service.RemediationService._parse_structured_generation_response(
            raw,
            target_method="com.example.Foo.foo()",
            original_method_lines=["public void foo() {}"],
        )
        self.assertFalse(parsed["raw_response_valid"])
        self.assertTrue((parsed["schema_error"] or "").startswith("invalid_json"))

    def test_parse_structured_generation_rejects_missing_fields(self):
        raw = '{"decision":"apply_edits","edits":[]}'
        parsed = self.service.RemediationService._parse_structured_generation_response(
            raw,
            target_method="com.example.Foo.foo()",
            original_method_lines=["public void foo() {}"],
        )
        self.assertFalse(parsed["raw_response_valid"])
        self.assertIn("schema_mismatch", parsed["schema_error"])

    def test_parse_structured_generation_rejects_empty_edits(self):
        raw = json.dumps({"decision": "apply_edits", "edits": [], "reason": ""})
        parsed = self.service.RemediationService._parse_structured_generation_response(
            raw,
            target_method="com.example.Foo.foo()",
            original_method_lines=["public void foo() {}"],
        )
        self.assertFalse(parsed["raw_response_valid"])
        self.assertEqual(parsed["schema_error"], "empty_edits")

    def test_parse_structured_generation_rejects_empty_no_fix_reason(self):
        raw = _structured_no_fix("   ")
        parsed = self.service.RemediationService._parse_structured_generation_response(
            raw,
            target_method="com.example.Foo.foo()",
            original_method_lines=["public void foo() {}"],
        )
        self.assertFalse(parsed["raw_response_valid"])
        self.assertIn("no_fix requires reason", parsed["schema_error"])

    def test_parse_structured_generation_rejects_non_string_edit_lines(self):
        raw = json.dumps(
            {
                "decision": "apply_edits",
                "edits": [
                    {
                        "start_line": 1,
                        "end_line": 1,
                        "original_lines": ["public void foo() {}"],
                        "replacement_lines": ["public void foo() {", 123, "}"],
                    }
                ],
                "reason": "",
            }
        )
        parsed = self.service.RemediationService._parse_structured_generation_response(
            raw,
            target_method="com.example.Foo.foo()",
            original_method_lines=["public void foo() {}"],
        )
        self.assertFalse(parsed["raw_response_valid"])
        self.assertIn("edit_lines_must_contain_strings", parsed["schema_error"])

    def test_parse_structured_generation_rejects_original_mismatch(self):
        raw = _structured_apply_edits(
            original_method='public void foo() { System.out.println("old"); }',
            replacement_method='public void foo() { System.out.println("ok"); }',
        )
        parsed = self.service.RemediationService._parse_structured_generation_response(
            raw,
            target_method="com.example.Foo.foo()",
            original_method_lines=['public void foo() { System.out.println("DIFFERENT"); }'],
        )
        self.assertFalse(parsed["raw_response_valid"])
        self.assertEqual(parsed["schema_error"], "edit_original_mismatch")

    def test_parse_structured_generation_accepts_declared_end_line_mismatch(self):
        original = [
            "@Override",
            "public void foo() {",
            '    System.out.println("old");',
            "}",
        ]
        replacement = [
            "@Override",
            "public void foo() {",
            '    System.out.println("ok");',
            "}",
        ]
        raw = _structured_apply_edits(
            original_method=original,
            replacement_method=replacement,
            start_line=1,
            end_line=2,
        )
        parsed = self.service.RemediationService._parse_structured_generation_response(
            raw,
            target_method="com.example.Foo.foo()",
            original_method_lines=original,
        )
        self.assertTrue(parsed["raw_response_valid"])
        self.assertIn('System.out.println("ok")', parsed["replacement_method_code"])

    def test_parse_structured_generation_accepts_indent_only_original_line_drift(self):
        original = [
            "public void hash() {",
            '    java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");',
            "}",
        ]
        raw = _structured_apply_edits(
            original_method=[
                "public void hash() {",
                'java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");',
                "}",
            ],
            replacement_method=[
                "public void hash() {",
                'java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");',
                "}",
            ],
            start_line=1,
            end_line=3,
        )
        parsed = self.service.RemediationService._parse_structured_generation_response(
            raw,
            target_method="com.example.Foo.hash()",
            original_method_lines=original,
        )
        self.assertTrue(parsed["raw_response_valid"])
        self.assertIn('MessageDigest.getInstance("SHA-256")', parsed["replacement_method_code"])

    def test_parse_structured_generation_accepts_unique_local_exact_match(self):
        original = [
            "@Override",
            "public void foo() {",
            '    System.out.println("old");',
            "}",
        ]
        replacement = [
            "@Override",
            "public void foo() {",
            '    System.out.println("ok");',
            "}",
        ]
        raw = _structured_apply_edits(
            original_method=original,
            replacement_method=replacement,
            start_line=2,
            end_line=5,
        )
        parsed = self.service.RemediationService._parse_structured_generation_response(
            raw,
            target_method="com.example.Foo.foo()",
            original_method_lines=original,
        )
        self.assertTrue(parsed["raw_response_valid"])
        self.assertIn('System.out.println("ok")', parsed["replacement_method_code"])

    def test_parse_structured_generation_accepts_out_of_order_non_overlapping_edits(self):
        raw = json.dumps(
            {
                "decision": "apply_edits",
                "edits": [
                    {
                        "start_line": 4,
                        "end_line": 4,
                        "original_lines": ['    call("DES");'],
                        "replacement_lines": ['    call("AES");'],
                    },
                    {
                        "start_line": 2,
                        "end_line": 2,
                        "original_lines": ['    int size = 8;'],
                        "replacement_lines": ['    int size = 16;'],
                    },
                ],
                "reason": "",
            }
        )
        original = [
            "public void foo() {",
            "    int size = 8;",
            "    setup();",
            '    call("DES");',
            "}",
        ]
        parsed = self.service.RemediationService._parse_structured_generation_response(
            raw,
            target_method="com.example.Foo.foo()",
            original_method_lines=original,
        )
        self.assertTrue(parsed["raw_response_valid"])
        self.assertIn('int size = 16;', parsed["replacement_method_code"])
        self.assertIn('call("AES");', parsed["replacement_method_code"])

    def test_parse_structured_generation_accepts_adjacent_non_overlapping_edits(self):
        raw = json.dumps(
            {
                "decision": "apply_edits",
                "edits": [
                    {
                        "start_line": 2,
                        "end_line": 2,
                        "original_lines": ['    byte[] iv = random.generateSeed(8);'],
                        "replacement_lines": ['    byte[] iv = random.generateSeed(12);'],
                    },
                    {
                        "start_line": 3,
                        "end_line": 4,
                        "original_lines": [
                            '    javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("DES/CBC/PKCS5Padding");',
                            '    javax.crypto.SecretKey key = javax.crypto.KeyGenerator.getInstance("DES").generateKey();',
                        ],
                        "replacement_lines": [
                            '    javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");',
                            '    javax.crypto.SecretKey key = javax.crypto.KeyGenerator.getInstance("AES").generateKey();',
                        ],
                    },
                ],
                "reason": "",
            }
        )
        original = [
            "public void foo() throws Exception {",
            "    byte[] iv = random.generateSeed(8);",
            '    javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("DES/CBC/PKCS5Padding");',
            '    javax.crypto.SecretKey key = javax.crypto.KeyGenerator.getInstance("DES").generateKey();',
            "}",
        ]
        parsed = self.service.RemediationService._parse_structured_generation_response(
            raw,
            target_method="com.example.Foo.foo()",
            original_method_lines=original,
        )
        self.assertTrue(parsed["raw_response_valid"])
        self.assertIn('generateSeed(12)', parsed["replacement_method_code"])
        self.assertIn('Cipher.getInstance("AES/GCM/NoPadding")', parsed["replacement_method_code"])

    def test_parse_structured_generation_ignores_exact_noop_edits(self):
        raw = json.dumps(
            {
                "decision": "apply_edits",
                "edits": [
                    {
                        "start_line": 2,
                        "end_line": 2,
                        "original_lines": ['    int size = 8;'],
                        "replacement_lines": ['    int size = 16;'],
                    },
                    {
                        "start_line": 3,
                        "end_line": 3,
                        "original_lines": ['    call("DES");'],
                        "replacement_lines": ['    call("AES");'],
                    },
                    {
                        "start_line": 4,
                        "end_line": 4,
                        "original_lines": ["    finish();"],
                        "replacement_lines": ["    finish();"],
                    },
                ],
                "reason": "",
            }
        )
        original = [
            "public void foo() {",
            "    int size = 8;",
            '    call("DES");',
            "    finish();",
            "}",
        ]
        parsed = self.service.RemediationService._parse_structured_generation_response(
            raw,
            target_method="com.example.Foo.foo()",
            original_method_lines=original,
        )
        self.assertTrue(parsed["raw_response_valid"])
        self.assertIn("int size = 16;", parsed["replacement_method_code"])
        self.assertIn('call("AES");', parsed["replacement_method_code"])
        self.assertIn("finish();", parsed["replacement_method_code"])

    def test_parse_structured_generation_merges_overlapping_exact_content_edits(self):
        raw = json.dumps(
            {
                "decision": "apply_edits",
                "edits": [
                    {
                        "start_line": 2,
                        "end_line": 3,
                        "original_lines": [
                            "    int size = 8;",
                            '    call("DES");',
                        ],
                        "replacement_lines": [
                            "    int size = 16;",
                            '    call("AES");',
                        ],
                    },
                    {
                        "start_line": 3,
                        "end_line": 4,
                        "original_lines": [
                            '    call("DES");',
                            "    finish();",
                        ],
                        "replacement_lines": [
                            '    call("AES");',
                            "    finish();",
                        ],
                    },
                ],
                "reason": "",
            }
        )
        original = [
            "public void foo() {",
            "    int size = 8;",
            '    call("DES");',
            "    finish();",
            "}",
        ]
        parsed = self.service.RemediationService._parse_structured_generation_response(
            raw,
            target_method="com.example.Foo.foo()",
            original_method_lines=original,
        )
        self.assertTrue(parsed["raw_response_valid"])
        self.assertIn('int size = 16;', parsed["replacement_method_code"])
        self.assertIn('call("AES");', parsed["replacement_method_code"])

    def test_parse_structured_generation_rejects_ambiguous_local_exact_match(self):
        raw = json.dumps(
            {
                "decision": "apply_edits",
                "edits": [
                    {
                        "start_line": 1,
                        "end_line": 1,
                        "original_lines": ['    keep();'],
                        "replacement_lines": ['    fix();'],
                    }
                ],
                "reason": "",
            }
        )
        original = [
            "public void foo() {",
            "    keep();",
            "    keep();",
            "}",
        ]
        parsed = self.service.RemediationService._parse_structured_generation_response(
            raw,
            target_method="com.example.Foo.foo()",
            original_method_lines=original,
        )
        self.assertFalse(parsed["raw_response_valid"])
        self.assertEqual(parsed["schema_error"], "edit_original_mismatch")

    def test_parse_structured_generation_accepts_benchmarktest01017_tail_noop_payload(self):
        raw = json.dumps(
            {
                "decision": "apply_edits",
                "edits": [
                    {
                        "start_line": 27,
                        "end_line": 28,
                        "original_lines": [
                            "javax.crypto.Cipher c =",
                            '                    javax.crypto.Cipher.getInstance("DES/CBC/PKCS5Padding", "SunJCE");',
                        ],
                        "replacement_lines": [
                            "javax.crypto.Cipher c =",
                            '                    javax.crypto.Cipher.getInstance("AES/GCM/NoPadding", "SunJCE");',
                        ],
                    },
                    {
                        "start_line": 30,
                        "end_line": 30,
                        "original_lines": [
                            '            javax.crypto.SecretKey key = javax.crypto.KeyGenerator.getInstance("DES").generateKey();'
                        ],
                        "replacement_lines": [
                            '            javax.crypto.SecretKey key = javax.crypto.KeyGenerator.getInstance("AES").generateKey();'
                        ],
                    },
                    {
                        "start_line": 24,
                        "end_line": 24,
                        "original_lines": ["        byte[] iv = random.generateSeed(8); // DES requires 8 byte keys"],
                        "replacement_lines": ["        byte[] iv = random.generateSeed(12); // AES-GCM requires 12 byte IV"],
                    },
                    {
                        "start_line": 31,
                        "end_line": 32,
                        "original_lines": [
                            "            java.security.spec.AlgorithmParameterSpec paramSpec =",
                            "                    new javax.crypto.spec.IvParameterSpec(iv);",
                        ],
                        "replacement_lines": [
                            "            java.security.spec.AlgorithmParameterSpec paramSpec =",
                            "                    new javax.crypto.spec.GCMParameterSpec(128, iv);",
                        ],
                    },
                    {
                        "start_line": 33,
                        "end_line": 33,
                        "original_lines": ["            c.init(javax.crypto.Cipher.ENCRYPT_MODE, key, paramSpec);"],
                        "replacement_lines": ["            c.init(javax.crypto.Cipher.ENCRYPT_MODE, key, paramSpec);"],
                    },
                    {
                        "start_line": 118,
                        "end_line": 118,
                        "original_lines": [
                            '        response.getWriter().println("Crypto Test javax.crypto.Cipher.getInstance(java.lang.String,java.lang.String) executed");'
                        ],
                        "replacement_lines": [
                            '        response.getWriter().println("Crypto Test javax.crypto.Cipher.getInstance(java.lang.String,java.lang.String) executed");'
                        ],
                    },
                    {
                        "start_line": 116,
                        "end_line": 117,
                        "original_lines": [
                            '        response.getWriter().println("Crypto Test javax.crypto.Cipher.getInstance(java.lang.String,java.lang.String) executed");',
                            "    } // end doPost",
                        ],
                        "replacement_lines": [
                            '        response.getWriter().println("Crypto Test javax.crypto.Cipher.getInstance(java.lang.String,java.lang.String) executed");',
                            "    } // end doPost",
                        ],
                    },
                ],
                "reason": "",
            }
        )
        original = [
            "public void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {",
            *[f"        // filler {idx}" for idx in range(2, 24)],
            "        byte[] iv = random.generateSeed(8); // DES requires 8 byte keys",
            "        javax.crypto.Cipher before = null;",
            "            javax.crypto.Cipher c =",
            '                    javax.crypto.Cipher.getInstance("DES/CBC/PKCS5Padding", "SunJCE");',
            "            // Prepare the cipher to encrypt",
            '            javax.crypto.SecretKey key = javax.crypto.KeyGenerator.getInstance("DES").generateKey();',
            "            java.security.spec.AlgorithmParameterSpec paramSpec =",
            "                    new javax.crypto.spec.IvParameterSpec(iv);",
            "            c.init(javax.crypto.Cipher.ENCRYPT_MODE, key, paramSpec);",
            *[f"        // filler {idx}" for idx in range(34, 116)],
            "        response.getWriter()",
            "                .println(",
            '                        "Crypto Test javax.crypto.Cipher.getInstance(java.lang.String,java.lang.String) executed");',
            "    }",
        ]
        parsed = self.service.RemediationService._parse_structured_generation_response(
            raw,
            target_method="org.owasp.benchmark.testcode.BenchmarkTest01017.doPost(HttpServletRequest,HttpServletResponse)",
            original_method_lines=original,
        )
        self.assertTrue(parsed["raw_response_valid"])
        self.assertIn('Cipher.getInstance("AES/GCM/NoPadding", "SunJCE")', parsed["replacement_method_code"])
        self.assertIn('KeyGenerator.getInstance("AES")', parsed["replacement_method_code"])
        self.assertIn("GCMParameterSpec(128, iv)", parsed["replacement_method_code"])

    def test_parse_structured_generation_normalizes_embedded_newlines_in_edit_lines(self):
        original = ['@Override', 'public void hash() {', '    System.out.println("old");', '}']
        replacement = ['@Override\\npublic void hash() {', '    System.out.println("ok");', '}']
        raw = _structured_apply_edits(
            original_method=original,
            replacement_method=replacement,
            start_line=1,
            end_line=4,
        )
        parsed = self.service.RemediationService._parse_structured_generation_response(
            raw,
            target_method="com.example.Foo.hash()",
            original_method_lines=original,
        )
        self.assertTrue(parsed["raw_response_valid"])
        self.assertIn("\npublic void hash()", parsed["replacement_method_code"])
        self.assertNotIn("\\n", parsed["replacement_method_code"])

    def test_parse_structured_generation_rejects_invalid_java_method_syntax(self):
        original = ['public void hash() {', '    System.out.println("old");', '}']
        raw = _structured_apply_edits(
            original_method=original,
            replacement_method='public void hash() { System.out.println("oops"; }',
            start_line=1,
            end_line=3,
        )
        parsed = self.service.RemediationService._parse_structured_generation_response(
            raw,
            target_method="com.example.Foo.hash()",
            original_method_lines=original,
        )
        self.assertFalse(parsed["raw_response_valid"])
        self.assertIn("invalid_java_syntax", parsed["schema_error"])

    def test_build_remediation_plan_extracts_constructor_chain_contract(self):
        from codegraph.remediation.planning import build_remediation_plan

        original = "\n".join(
            [
                "public void random() {",
                "    float rand = new java.util.Random().nextFloat();",
                "}",
            ]
        )
        plan = build_remediation_plan(original)

        self.assertEqual(plan.transformation_class, "receiver_chain_upgrade")
        self.assertEqual(len(plan.terminal_invocation_contracts), 1)
        contract = plan.terminal_invocation_contracts[0]
        self.assertEqual(contract.member, "nextFloat")
        self.assertEqual(contract.arg_count, 0)
        self.assertEqual(contract.occurrence_count, 1)
        self.assertEqual(contract.source_kind, "constructor_chain")

    def test_build_remediation_plan_extracts_factory_chain_contract(self):
        from codegraph.remediation.planning import build_remediation_plan

        original = "\n".join(
            [
                "public byte[] hash(byte[] input) throws Exception {",
                '    return java.security.MessageDigest.getInstance("MD5").digest(input);',
                "}",
            ]
        )
        plan = build_remediation_plan(original)

        self.assertEqual(plan.transformation_class, "receiver_chain_upgrade")
        self.assertEqual(len(plan.terminal_invocation_contracts), 1)
        contract = plan.terminal_invocation_contracts[0]
        self.assertEqual(contract.member, "digest")
        self.assertEqual(contract.arg_count, 1)
        self.assertEqual(contract.source_kind, "factory_chain")

    def test_parse_structured_generation_rejects_plan_invariant_drop(self):
        from codegraph.remediation.planning import build_remediation_plan

        original = [
            "public void random() {",
            "    float rand = new java.util.Random().nextFloat();",
            "}",
        ]
        replacement = [
            "public void random() {",
            "    java.security.SecureRandom rand = new java.security.SecureRandom();",
            "}",
        ]
        raw = _structured_apply_edits(
            original_method=original,
            replacement_method=replacement,
            start_line=1,
            end_line=3,
        )
        parsed = self.service.RemediationService._parse_structured_generation_response(
            raw,
            target_method="com.example.Foo.random()",
            original_method_lines=original,
            plan=build_remediation_plan("\n".join(original)),
        )
        self.assertFalse(parsed["raw_response_valid"])
        self.assertEqual(
            parsed["schema_error"],
            "plan_invariant_violation: missing_terminal_invocation:nextFloat/0",
        )

    def test_parse_structured_generation_accepts_plan_invariant_preserved_via_local_variable(self):
        from codegraph.remediation.planning import build_remediation_plan

        original = [
            "public void random() {",
            "    float rand = new java.util.Random().nextFloat();",
            "}",
        ]
        replacement = [
            "public void random() {",
            "    java.security.SecureRandom secureRandom = new java.security.SecureRandom();",
            "    float rand = secureRandom.nextFloat();",
            "}",
        ]
        raw = _structured_apply_edits(
            original_method=original,
            replacement_method=replacement,
            start_line=1,
            end_line=3,
        )
        parsed = self.service.RemediationService._parse_structured_generation_response(
            raw,
            target_method="com.example.Foo.random()",
            original_method_lines=original,
            plan=build_remediation_plan("\n".join(original)),
        )
        self.assertTrue(parsed["raw_response_valid"])

    def test_parse_structured_generation_rejects_multiline_string_literal(self):
        original = [
            "public void hash() {",
            '    String x = "safe";',
            "}",
        ]
        raw = _structured_apply_edits(
            original_method=original,
            replacement_method=[
                "public void hash() {",
                '    String x = "',
                '";',
                "}",
            ],
            start_line=1,
            end_line=3,
        )
        parsed = self.service.RemediationService._parse_structured_generation_response(
            raw,
            target_method="com.example.Foo.hash()",
            original_method_lines=original,
        )
        self.assertFalse(parsed["raw_response_valid"])
        self.assertEqual(parsed["schema_error"], "invalid_java_syntax: multiline_string_literal")

    def test_parse_structured_generation_rejects_method_name_mismatch(self):
        original = ["public void hash() { return; }"]
        raw = _structured_apply_edits(
            original_method=original,
            replacement_method="public void wrongName() { return; }",
        )
        parsed = self.service.RemediationService._parse_structured_generation_response(
            raw,
            target_method="com.example.Foo.hash()",
            original_method_lines=original,
        )
        self.assertFalse(parsed["raw_response_valid"])
        self.assertEqual(parsed["schema_error"], "method_name_mismatch")

    def test_parse_structured_generation_rejects_parameter_count_mismatch(self):
        original = ["public void hash(HttpServletRequest a, HttpServletResponse b) { return; }"]
        raw = _structured_apply_edits(
            original_method=original,
            replacement_method="public void hash(String a) { return; }",
        )
        parsed = self.service.RemediationService._parse_structured_generation_response(
            raw,
            target_method="com.example.Foo.hash(HttpServletRequest,HttpServletResponse)",
            original_method_lines=original,
        )
        self.assertFalse(parsed["raw_response_valid"])
        self.assertEqual(parsed["schema_error"], "parameter_count_mismatch")

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
            "numbered_method_source": "1: public void hash() { java.security.MessageDigest.getInstance(\"MD5\"); }",
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
                "exact_method_source": "public void hash() { }",
            }
            remediation._resolve_file_path = lambda *_args, **_kwargs: src_path  # type: ignore[method-assign]
            remediation.propose_method_edits = (  # type: ignore[method-assign]
                lambda *_args, **_kwargs: {
                    "decision": "apply_edits",
                    "edits": None,
                    "replacement_method_lines": None,
                    "replacement_method_code": None,
                    "reason": "",
                    "schema_error": "invalid_java_syntax: expected \")\"",
                    "generation": {
                        "decision": "apply_edits",
                        "edits": None,
                        "replacement_method_lines": None,
                        "replacement_method_code": None,
                        "reason": "",
                        "raw_response_valid": False,
                        "schema_error": "invalid_java_syntax: expected \")\"",
                    },
                    "raw_output": '{"decision":"apply_edits"}',
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
            self.assertIn("invalid_java_syntax", out.get("errors", []))

    def test_retry_error_summary_is_structural(self):
        self.assertEqual(self.service._summarize_retry_error("invalid_java_syntax: JavaSyntaxError"), "invalid_java_syntax")
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
                "exact_method_source": 'public void doPost(...) { MessageDigest.getInstance("MD5"); }',
            }
            remediation._resolve_file_path = lambda *_args, **_kwargs: src_path  # type: ignore[method-assign]
            remediation.propose_method_edits = (  # type: ignore[method-assign]
                lambda *_args, **_kwargs: {
                    "decision": "apply_edits",
                    "edits": [
                        {
                            "start_line": 1,
                            "end_line": 1,
                            "original_lines": ['public void doPost(...) { MessageDigest.getInstance("MD5"); }'],
                            "replacement_lines": ["public void doPost(...) { /* sha-256 */ }"],
                        }
                    ],
                    "replacement_method_lines": ["public void doPost(...) { /* sha-256 */ }"],
                    "replacement_method_code": "public void doPost(...) { /* sha-256 */ }",
                    "reason": None,
                    "schema_error": None,
                    "generation": {
                        "decision": "apply_edits",
                        "edits": [
                            {
                                "start_line": 1,
                                "end_line": 1,
                                "original_lines": ['public void doPost(...) { MessageDigest.getInstance("MD5"); }'],
                                "replacement_lines": ["public void doPost(...) { /* sha-256 */ }"],
                            }
                        ],
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
                    updated_content,
                    "void a() {}",
                    updated_method,
                )
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

            orig_psfc = svc_mod.process_single_file_content
            orig_policy_evaluator = svc_mod.PolicyEvaluator

            class RecordingPolicyEvaluator:
                def evaluate(self, _method_signature: str, *, source_path_override: str | None = None):
                    captured["source_path_override"] = source_path_override
                    if source_path_override:
                        captured["temp_file_content"] = Path(source_path_override).read_text(encoding="utf-8")
                    return {"violations": []}

            try:
                svc_mod.process_single_file_content = (
                    lambda path, content: captured["reingest_calls"].append((path, content))
                )
                svc_mod.PolicyEvaluator = RecordingPolicyEvaluator  # type: ignore[assignment]

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
            finally:
                svc_mod.process_single_file_content = orig_psfc
                svc_mod.PolicyEvaluator = orig_policy_evaluator

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
                "exact_method_source": 'public void doPost(...) { MessageDigest.getInstance("MD5"); }',
            }
            remediation._resolve_file_path = lambda *_args, **_kwargs: src_path  # type: ignore[method-assign]
            remediation.propose_method_edits = (  # type: ignore[method-assign]
                lambda *_args, **_kwargs: {
                    "decision": "apply_edits",
                    "edits": [
                        {
                            "start_line": 1,
                            "end_line": 1,
                            "original_lines": ['public void doPost(...) { MessageDigest.getInstance("MD5"); }'],
                            "replacement_lines": ["public void doPost(...) { /* sha-256 */ }"],
                        }
                    ],
                    "replacement_method_lines": ["public void doPost(...) { /* sha-256 */ }"],
                    "replacement_method_code": "public void doPost(...) { /* sha-256 */ }",
                    "reason": None,
                    "schema_error": None,
                    "generation": {
                        "decision": "apply_edits",
                        "edits": [
                            {
                                "start_line": 1,
                                "end_line": 1,
                                "original_lines": ['public void doPost(...) { MessageDigest.getInstance("MD5"); }'],
                                "replacement_lines": ["public void doPost(...) { /* sha-256 */ }"],
                            }
                        ],
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
            reingest_calls: list[tuple[str, str]] = []
            source_path_overrides: list[str | None] = []

            class BoomPolicyEvaluator:
                def evaluate(self, _method_signature: str, *, source_path_override: str | None = None):
                    source_path_overrides.append(source_path_override)
                    raise RuntimeError("boom")

            try:
                svc_mod.process_single_file_content = lambda path, content: reingest_calls.append((path, content))
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
