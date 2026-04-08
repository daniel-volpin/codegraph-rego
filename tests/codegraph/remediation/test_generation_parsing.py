import json
import unittest

from tests.codegraph.remediation._test_helpers import RemediationTestBase, _structured_apply_edits, _structured_no_fix


class GenerationParsingTests(RemediationTestBase):
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
                        "original_lines": ["    int size = 8;"],
                        "replacement_lines": ["    int size = 16;"],
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
        self.assertIn("int size = 16;", parsed["replacement_method_code"])
        self.assertIn('call("AES");', parsed["replacement_method_code"])

    def test_parse_structured_generation_accepts_adjacent_non_overlapping_edits(self):
        raw = json.dumps(
            {
                "decision": "apply_edits",
                "edits": [
                    {
                        "start_line": 2,
                        "end_line": 2,
                        "original_lines": ["    byte[] iv = random.generateSeed(8);"],
                        "replacement_lines": ["    byte[] iv = random.generateSeed(12);"],
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
        self.assertIn("generateSeed(12)", parsed["replacement_method_code"])
        self.assertIn('Cipher.getInstance("AES/GCM/NoPadding")', parsed["replacement_method_code"])

    def test_parse_structured_generation_ignores_exact_noop_edits(self):
        raw = json.dumps(
            {
                "decision": "apply_edits",
                "edits": [
                    {
                        "start_line": 2,
                        "end_line": 2,
                        "original_lines": ["    int size = 8;"],
                        "replacement_lines": ["    int size = 16;"],
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
        self.assertIn("int size = 16;", parsed["replacement_method_code"])
        self.assertIn('call("AES");', parsed["replacement_method_code"])

    def test_parse_structured_generation_rejects_ambiguous_local_exact_match(self):
        raw = json.dumps(
            {
                "decision": "apply_edits",
                "edits": [
                    {
                        "start_line": 1,
                        "end_line": 1,
                        "original_lines": ["    keep();"],
                        "replacement_lines": ["    fix();"],
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
                        "replacement_lines": [
                            "        byte[] iv = random.generateSeed(12); // AES-GCM requires 12 byte IV"
                        ],
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
        original = ["@Override", "public void hash() {", '    System.out.println("old");', "}"]
        replacement = ["@Override\\npublic void hash() {", '    System.out.println("ok");', "}"]
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
        original = ["public void hash() {", '    System.out.println("old");', "}"]
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


if __name__ == "__main__":
    unittest.main()
