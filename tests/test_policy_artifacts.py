import json
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _load_json(path: Path):
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


class TestPolicyArtifacts(unittest.TestCase):
    def test_benchmark_rule_artifacts_are_present(self):
        catalog = _load_json(PROJECT_ROOT / "policy" / "catalog.json")
        controls = catalog.get("controls", [])
        ids = {item.get("id") for item in controls if isinstance(item, dict)}
        self.assertIn("ISO-A.10-WEAK-RANDOM", ids)
        self.assertIn("ISO-A.8-PATH-TRAVERSAL", ids)
        self.assertIn("ISO-A.8-CMD-INJECTION", ids)
        self.assertIn("ISO-A.8-LDAP-INJECTION", ids)
        self.assertIn("ISO-A.8-XPATH-INJECTION", ids)

        iso_rules = _load_json(PROJECT_ROOT / "policy" / "iso_rules.json")
        rules = iso_rules.get("rules", [])
        rule_ids = {item.get("id") for item in rules if isinstance(item, dict)}
        self.assertIn("A.10-WEAK-RANDOM", rule_ids)
        self.assertIn("A.8-PATH-TRAVERSAL", rule_ids)
        self.assertIn("A.8-CMD-INJECTION", rule_ids)
        self.assertIn("A.8-LDAP-INJECTION", rule_ids)
        self.assertIn("A.8-XPATH-INJECTION", rule_ids)

        mapping = _load_json(PROJECT_ROOT / "configs" / "control_mapping.json")
        categories = mapping.get("categories", [])
        rego_rules = {
            rule for entry in categories if isinstance(entry, dict) for rule in (entry.get("rego_rules") or [])
        }
        self.assertIn("ISO-A.10-WEAK-RANDOM", rego_rules)
        self.assertIn("ISO-A.8-PATH-TRAVERSAL", rego_rules)
        self.assertIn("ISO-A.8-CMD-INJECTION", rego_rules)
        self.assertIn("ISO-A.8-LDAP-INJECTION", rego_rules)
        self.assertIn("ISO-A.8-XPATH-INJECTION", rego_rules)

        self.assertIn("ISO-A.8-SQL-INJECTION", ids)
        self.assertIn("A.8-SQL-INJECTION", rule_ids)
        self.assertIn("ISO-A.8-SQL-INJECTION", rego_rules)

        access_rego = (PROJECT_ROOT / "policy" / "iso_27001_access.rego").read_text(encoding="utf-8")
        crypto_rego = (PROJECT_ROOT / "policy" / "iso_27001_crypto.rego").read_text(encoding="utf-8")
        injection_rego = (PROJECT_ROOT / "policy" / "iso_27001_injection.rego").read_text(encoding="utf-8")
        self.assertIn('violation_record("ISO-A.10-WEAK-RANDOM"', crypto_rego)
        self.assertIn('violation_record("ISO-A.8-SQL-INJECTION"', injection_rego)
        self.assertIn('violation_record("ISO-A.8-PATH-TRAVERSAL"', injection_rego)
        self.assertIn('violation_record("ISO-A.8-CMD-INJECTION"', injection_rego)
        self.assertIn('violation_record("ISO-A.8-LDAP-INJECTION"', injection_rego)
        self.assertIn('violation_record("ISO-A.8-XPATH-INJECTION"', injection_rego)
        self.assertIn('violation_record("ISO-A.9.4.1"', access_rego)


if __name__ == "__main__":
    unittest.main()
