import json
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _load_json(path: Path):
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


class TestPolicyArtifacts(unittest.TestCase):
    def test_cwe330_rule_is_present_in_all_artifacts(self):
        catalog = _load_json(PROJECT_ROOT / "policy" / "catalog.json")
        controls = catalog.get("controls", [])
        ids = {item.get("id") for item in controls if isinstance(item, dict)}
        self.assertIn("ISO-A.10-WEAK-RANDOM", ids)

        iso_rules = _load_json(PROJECT_ROOT / "policy" / "iso_rules.json")
        rules = iso_rules.get("rules", [])
        rule_ids = {item.get("id") for item in rules if isinstance(item, dict)}
        self.assertIn("A.10-WEAK-RANDOM", rule_ids)

        mapping = _load_json(PROJECT_ROOT / "configs" / "control_mapping.json")
        categories = mapping.get("categories", [])
        rego_rules = {
            rule
            for entry in categories
            if isinstance(entry, dict)
            for rule in (entry.get("rego_rules") or [])
        }
        self.assertIn("ISO-A.10-WEAK-RANDOM", rego_rules)

        rego_text = (PROJECT_ROOT / "policy" / "iso_27001_access.rego").read_text(
            encoding="utf-8"
        )
        self.assertIn('violation_record("ISO-A.10-WEAK-RANDOM"', rego_text)

    def test_cwe89_rule_is_present_in_all_artifacts(self):
        catalog = _load_json(PROJECT_ROOT / "policy" / "catalog.json")
        controls = catalog.get("controls", [])
        ids = {item.get("id") for item in controls if isinstance(item, dict)}
        self.assertIn("ISO-A.8-SQL-INJECTION", ids)

        iso_rules = _load_json(PROJECT_ROOT / "policy" / "iso_rules.json")
        rules = iso_rules.get("rules", [])
        rule_ids = {item.get("id") for item in rules if isinstance(item, dict)}
        self.assertIn("A.8-SQL-INJECTION", rule_ids)

        mapping = _load_json(PROJECT_ROOT / "configs" / "control_mapping.json")
        categories = mapping.get("categories", [])
        rego_rules = {
            rule
            for entry in categories
            if isinstance(entry, dict)
            for rule in (entry.get("rego_rules") or [])
        }
        self.assertIn("ISO-A.8-SQL-INJECTION", rego_rules)

        rego_text = (PROJECT_ROOT / "policy" / "iso_27001_access.rego").read_text(
            encoding="utf-8"
        )
        self.assertIn('violation_record("ISO-A.8-SQL-INJECTION"', rego_text)


if __name__ == "__main__":
    unittest.main()

