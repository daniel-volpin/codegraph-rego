"""Pin the structure and CodeGraph-id mapping of the SemGrep rule files."""

from __future__ import annotations

import unittest
from pathlib import Path

import yaml

from baselines.semgrep.runner import DEFAULT_RULES_DIR

EXPECTED_RULES: dict[str, str] = {
    "iso-a10-weak-hash": "ISO-A.10-WEAK-HASH",
    "iso-a10-weak-crypto": "ISO-A.10-WEAK-CRYPTO",
    "iso-a10-weak-random": "ISO-A.10-WEAK-RANDOM",
    "iso-a8-sql-injection": "ISO-A.8-SQL-INJECTION",
    "iso-a8-path-traversal": "ISO-A.8-PATH-TRAVERSAL",
    "iso-a8-cmd-injection": "ISO-A.8-CMD-INJECTION",
    "iso-a8-ldap-injection": "ISO-A.8-LDAP-INJECTION",
    "iso-a8-xpath-injection": "ISO-A.8-XPATH-INJECTION",
}


def _load_rules() -> dict[str, dict]:
    bucket: dict[str, dict] = {}
    for path in sorted(Path(DEFAULT_RULES_DIR).glob("*.yaml")):
        with path.open("r", encoding="utf-8") as handle:
            payload = yaml.safe_load(handle)
        for rule in payload.get("rules", []):
            bucket[rule["id"]] = rule
    return bucket


class RulesMetadataTests(unittest.TestCase):
    """The 8 SemGrep rules must mirror CodeGraph's 8 active CWE families."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.rules = _load_rules()

    def test_eight_rules_present_and_no_extras(self) -> None:
        self.assertEqual(set(self.rules.keys()), set(EXPECTED_RULES.keys()))

    def test_each_rule_targets_java(self) -> None:
        for rule_id, rule in self.rules.items():
            self.assertEqual(
                rule.get("languages"),
                ["java"],
                msg=f"rule {rule_id} must target only [java]",
            )

    def test_each_rule_maps_to_codegraph_violation_id(self) -> None:
        for rule_id, expected_cg_id in EXPECTED_RULES.items():
            with self.subTest(rule_id=rule_id):
                metadata = self.rules[rule_id].get("metadata", {})
                self.assertEqual(metadata.get("codegraph_violation_id"), expected_cg_id)

    def test_each_rule_carries_iso_and_cwe(self) -> None:
        for rule_id, rule in self.rules.items():
            with self.subTest(rule_id=rule_id):
                metadata = rule.get("metadata", {})
                self.assertIn("iso27001", metadata, f"{rule_id}: missing iso27001 tag")
                self.assertIn("cwe", metadata, f"{rule_id}: missing cwe tag")

    def test_each_rule_has_severity_and_message(self) -> None:
        for rule_id, rule in self.rules.items():
            with self.subTest(rule_id=rule_id):
                self.assertIn(rule.get("severity"), {"INFO", "WARNING", "ERROR"})
                self.assertTrue(str(rule.get("message", "")).strip())


if __name__ == "__main__":
    unittest.main()
