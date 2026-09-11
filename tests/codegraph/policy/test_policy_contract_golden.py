import json
import logging
import shutil
import unittest

from codegraph.policy.runtime.contracts import (
    ANALYSIS_FLAG_NAMES,
    HELPER_SUMMARY_BOOLEAN_FIELDS,
    HELPER_SUMMARY_INT_FIELDS,
    HELPER_SUMMARY_LIST_FIELDS,
    normalize_policy_bundle_mapping,
    serialize_policy_bundle,
    serialize_policy_input_envelope,
)
from codegraph.policy.runtime.opa import evaluate_bundle, normalize_violation_payload
from tests._support import PROJECT_ROOT

FIXTURE_DIR = PROJECT_ROOT / "tests" / "fixtures" / "policy_contract"
OPA_AVAILABLE = bool(shutil.which("opa"))
BENCHMARK_FIXTURE_MATRIX: dict[str, dict[str, str]] = {
    "CWE-22": {
        "positive": "path_tainted_detected.json",
        "negative": "path_safe_helper_suppressed.json",
    },
    "CWE-78": {
        "positive": "command_tainted_helper.json",
        "negative": "command_safe_helper_suppressed.json",
    },
    "CWE-89": {
        "positive": "sql_tainted_detected.json",
        "negative": "analysis_flags_null_safe_prepared_statement.json",
    },
    "CWE-90": {
        "positive": "ldap_tainted_detected.json",
        "negative": "ldap_safe_helper_suppressed.json",
    },
    "CWE-327": {
        "positive": "weak_crypto_des_detected.json",
        "negative": "weak_crypto_aes_gcm_safe.json",
    },
    "CWE-328": {
        "positive": "weak_hash_call_graph.json",
        "negative": "weak_hash_sha256_safe.json",
    },
    "CWE-330": {
        "positive": "weak_random_detected.json",
        "negative": "weak_random_secure_random_safe.json",
    },
    "CWE-643": {
        "positive": "xpath_tainted_detected.json",
        "negative": "xpath_safe_helper_suppressed.json",
    },
}


def _load_fixture(name: str) -> dict:
    with (FIXTURE_DIR / name).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _violation_ids(raw_output) -> set[str]:
    payloads = list(raw_output.keys()) if isinstance(raw_output, dict) else list(raw_output)
    normalized = [normalize_violation_payload(item, logging.getLogger(__name__)) for item in payloads]
    return {item.get("violation_id") for item in normalized if item}


class TestPolicyContractSerialization(unittest.TestCase):
    def test_serialize_policy_bundle_emits_canonical_keys(self) -> None:
        bundle = serialize_policy_bundle(
            {
                "target_method": "org.example.Foo.listUsers()",
                "graph_context": {},
                "source_code": None,
                "analysis_flags": None,
            }
        )

        self.assertEqual(
            set(bundle.keys()),
            {
                "target_method",
                "method_name",
                "class_fqn",
                "file_path",
                "start_line",
                "end_line",
                "modifiers",
                "source_code",
                "source_code_raw",
                "graph_context",
                "vector_context",
                "analysis_flags",
                "helper_summaries",
            },
        )
        self.assertEqual(bundle["source_code"], "")
        self.assertEqual(bundle["source_code_raw"], "")
        self.assertIsNone(bundle["analysis_flags"])
        self.assertEqual(
            bundle["graph_context"],
            {"annotations": [], "uses_fields": [], "calls": [], "callers": []},
        )

    def test_missing_optional_nested_fields_default_conservatively(self) -> None:
        bundle = serialize_policy_bundle({"target_method": "org.example.Foo.listUsers()", "graph_context": {}})

        self.assertEqual(bundle["source_code"], "")
        self.assertEqual(bundle["modifiers"], [])
        self.assertEqual(bundle["vector_context"], [])
        self.assertEqual(bundle["graph_context"]["annotations"], [])
        self.assertEqual(bundle["graph_context"]["uses_fields"], [])
        self.assertEqual(bundle["graph_context"]["calls"], [])
        self.assertEqual(bundle["graph_context"]["callers"], [])
        self.assertEqual(bundle["analysis_flags"], {key: False for key in ANALYSIS_FLAG_NAMES})
        self.assertEqual(bundle["helper_summaries"]["safe_constant_return_vars"], [])
        self.assertEqual(bundle["helper_summaries"]["tainted_return_vars"], [])
        for field_name in HELPER_SUMMARY_BOOLEAN_FIELDS:
            self.assertFalse(bundle["helper_summaries"][field_name])
        for field_name in HELPER_SUMMARY_INT_FIELDS:
            self.assertEqual(bundle["helper_summaries"][field_name], 0)

    def test_partial_analysis_flags_are_normalized_to_full_shape(self) -> None:
        bundle = serialize_policy_bundle(
            {
                "target_method": "org.example.Foo.hash()",
                "graph_context": {},
                "analysis_flags": {"md5_detected": True},
            }
        )

        self.assertTrue(bundle["analysis_flags"]["md5_detected"])
        missing_keys = set(ANALYSIS_FLAG_NAMES) - {"md5_detected"}
        for key in missing_keys:
            self.assertIn(key, bundle["analysis_flags"])
            self.assertFalse(bundle["analysis_flags"][key])

    def test_partial_helper_summaries_are_normalized_to_full_shape(self) -> None:
        bundle = serialize_policy_bundle(
            {
                "target_method": "org.example.Foo.exec()",
                "graph_context": {},
                "helper_summaries": {"tainted_return_vars": ["bar"], "tainted_return_used_in_command_sink": True},
            }
        )

        self.assertEqual(bundle["helper_summaries"]["tainted_return_vars"], ["bar"])
        self.assertTrue(bundle["helper_summaries"]["tainted_return_used_in_command_sink"])
        self.assertEqual(bundle["helper_summaries"]["safe_constant_return_vars"], [])
        for field_name in HELPER_SUMMARY_LIST_FIELDS:
            self.assertIn(field_name, bundle["helper_summaries"])

    def test_source_code_raw_survives_input_envelope_serialization(self) -> None:
        raw_source = 'Cipher.getInstance("DES/CBC/PKCS5Padding");'
        cleaned_source = "Cipher.getInstance(\"\");"

        envelope = serialize_policy_input_envelope(
            bundles=[
                {
                    "target_method": "org.example.Foo.encrypt()",
                    "graph_context": {},
                    "source_code": cleaned_source,
                    "source_code_raw": raw_source,
                }
            ],
            rules_catalog={},
            catalog=[],
        )

        bundle = envelope["bundles"][0]
        self.assertEqual(bundle["source_code"], cleaned_source)
        self.assertEqual(bundle["source_code_raw"], raw_source)

    def test_normalize_policy_bundle_mapping_rejects_non_mapping_graph_context(self) -> None:
        with self.assertRaisesRegex(TypeError, "graph_context must be a mapping"):
            normalize_policy_bundle_mapping(
                {"target_method": "org.example.Foo.bad()", "graph_context": "not-a-mapping"}
            )

    def test_normalize_policy_bundle_mapping_rejects_malformed_uses_fields(self) -> None:
        with self.assertRaisesRegex(TypeError, "uses_fields"):
            normalize_policy_bundle_mapping(
                {
                    "target_method": "org.example.Foo.bad()",
                    "graph_context": {"uses_fields": ["loggerField"]},
                }
            )

    def test_normalize_policy_bundle_mapping_rejects_non_mapping_helper_summaries(self) -> None:
        with self.assertRaisesRegex(TypeError, "helper_summaries must be a mapping"):
            normalize_policy_bundle_mapping(
                {
                    "target_method": "org.example.Foo.bad()",
                    "graph_context": {},
                    "helper_summaries": ["oops"],
                }
            )

    def test_normalize_policy_bundle_mapping_rejects_non_mapping_analysis_flags(self) -> None:
        with self.assertRaisesRegex(TypeError, "analysis_flags must be a mapping or None"):
            normalize_policy_bundle_mapping(
                {
                    "target_method": "org.example.Foo.bad()",
                    "graph_context": {},
                    "analysis_flags": ["oops"],
                }
            )


@unittest.skipUnless(OPA_AVAILABLE, "OPA CLI not available on PATH")
class TestPolicyContractGoldenFixtures(unittest.TestCase):
    def test_golden_fixtures_match_expected_violation_ids(self) -> None:
        for fixture_path in sorted(FIXTURE_DIR.glob("*.json")):
            with self.subTest(fixture=fixture_path.name):
                payload = _load_fixture(fixture_path.name)
                violations = evaluate_bundle(payload["bundle"])
                self.assertEqual(_violation_ids(violations), set(payload["expected_violation_ids"]))

    def test_benchmark_matrix_has_explicit_positive_and_negative_cases(self) -> None:
        for cwe_id, cases in BENCHMARK_FIXTURE_MATRIX.items():
            positive_fixture = cases["positive"]
            negative_fixture = cases["negative"]
            with self.subTest(cwe=cwe_id, case="positive", fixture=positive_fixture):
                payload = _load_fixture(positive_fixture)
                violations = evaluate_bundle(payload["bundle"])
                expected = set(payload["expected_violation_ids"])
                self.assertTrue(expected, f"{positive_fixture} must assert at least one violation")
                self.assertEqual(_violation_ids(violations), expected)
            with self.subTest(cwe=cwe_id, case="negative", fixture=negative_fixture):
                payload = _load_fixture(negative_fixture)
                violations = evaluate_bundle(payload["bundle"])
                expected = set(payload["expected_violation_ids"])
                self.assertEqual(expected, set(), f"{negative_fixture} must assert an explicit safe outcome")
                self.assertEqual(_violation_ids(violations), expected)
