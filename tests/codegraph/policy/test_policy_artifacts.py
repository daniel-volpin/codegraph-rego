import json
import re
import tempfile
import unittest
from pathlib import Path

from codegraph.benchmark_registry import (
    framework_demo_rule_ids,
    load_policy_registry,
    policy_catalog_entries_from_registry,
    policy_catalog_payload_from_registry,
    iso_rules_payload_from_registry,
)
from tests._support import PROJECT_ROOT


def _load_json(path: Path):
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _write_json(path: Path, payload) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


class TestPolicyArtifacts(unittest.TestCase):
    def test_registry_rule_ids_match_rego_and_compatibility_artifacts(self):
        catalog = _load_json(PROJECT_ROOT / "policy" / "catalog.json")
        controls = catalog.get("controls", [])
        catalog_ids = {item.get("id") for item in controls if isinstance(item, dict)}

        iso_rules = _load_json(PROJECT_ROOT / "policy" / "iso_rules.json")
        rules = iso_rules.get("rules", [])
        iso_rule_ids = {item.get("id") for item in rules if isinstance(item, dict)}

        registry = load_policy_registry()
        registry_rule_ids = {rule.id for rule in registry.rules}
        registry_iso_rule_ids = {rule.iso_rule_id for rule in registry.rules}

        access_rego = (PROJECT_ROOT / "policy" / "iso_27001_access.rego").read_text(encoding="utf-8")
        crypto_rego = (PROJECT_ROOT / "policy" / "iso_27001_crypto.rego").read_text(encoding="utf-8")
        injection_rego = (PROJECT_ROOT / "policy" / "iso_27001_injection.rego").read_text(encoding="utf-8")
        emitted_rule_ids = set(
            re.findall(r'violation_record\("([^"]+)"', "\n".join([access_rego, crypto_rego, injection_rego]))
        )

        self.assertEqual(registry_rule_ids, emitted_rule_ids)
        self.assertEqual(registry_rule_ids, catalog_ids)
        self.assertEqual(registry_iso_rule_ids, iso_rule_ids)

    def test_registry_payload_matches_compatibility_catalog_surface(self):
        derived_catalog = {"controls": policy_catalog_entries_from_registry()}
        file_catalog = _load_json(PROJECT_ROOT / "policy" / "catalog.json")
        self.assertEqual(derived_catalog, file_catalog)

        derived_iso_rules = iso_rules_payload_from_registry()
        file_iso_rules = _load_json(PROJECT_ROOT / "policy" / "iso_rules.json")
        self.assertEqual(derived_iso_rules, file_iso_rules)

        payload = policy_catalog_payload_from_registry()
        self.assertEqual(payload["framework_demo_rule_ids"], framework_demo_rule_ids())
        category_ids = {entry["category_id"] for entry in payload["benchmark_categories"]}
        self.assertIn("hash-md5", category_ids)
        self.assertIn("xpath-injection", category_ids)

    def test_registry_rejects_duplicate_rule_ids(self):
        payload = _load_json(PROJECT_ROOT / "configs" / "benchmark" / "policy_registry.json")
        payload["rules"].append(dict(payload["rules"][0]))
        with tempfile.TemporaryDirectory() as temp_dir:
            registry_path = Path(temp_dir) / "policy_registry.json"
            _write_json(registry_path, payload)
            with self.assertRaisesRegex(ValueError, "duplicate rule id"):
                load_policy_registry(registry_path.as_posix())

    def test_registry_rejects_alias_collision_with_rule_id(self):
        payload = _load_json(PROJECT_ROOT / "configs" / "benchmark" / "policy_registry.json")
        payload["rules"][0]["alias_ids"] = [payload["rules"][1]["id"]]
        with tempfile.TemporaryDirectory() as temp_dir:
            registry_path = Path(temp_dir) / "policy_registry.json"
            _write_json(registry_path, payload)
            with self.assertRaisesRegex(ValueError, "collides with a rule id"):
                load_policy_registry(registry_path.as_posix())

    def test_registry_rejects_missing_rego_module(self):
        payload = _load_json(PROJECT_ROOT / "configs" / "benchmark" / "policy_registry.json")
        payload["rules"][0]["rego_module"] = "policy/missing_module.rego"
        with tempfile.TemporaryDirectory() as temp_dir:
            registry_path = Path(temp_dir) / "policy_registry.json"
            _write_json(registry_path, payload)
            with self.assertRaisesRegex(ValueError, "missing module"):
                load_policy_registry(registry_path.as_posix())

    def test_registry_rejects_unknown_evidence_field_alias(self):
        payload = _load_json(PROJECT_ROOT / "configs" / "benchmark" / "policy_registry.json")
        payload["rules"][0]["evidence_fields"] = ["signature", "unknown_field"]
        with tempfile.TemporaryDirectory() as temp_dir:
            registry_path = Path(temp_dir) / "policy_registry.json"
            _write_json(registry_path, payload)
            with self.assertRaisesRegex(ValueError, "unknown evidence field"):
                load_policy_registry(registry_path.as_posix())


if __name__ == "__main__":
    unittest.main()
