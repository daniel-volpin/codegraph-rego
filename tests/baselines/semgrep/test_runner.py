"""Unit tests for the SemGrep wrapper (parsing, dataclasses, mapping)."""

from __future__ import annotations

import unittest

from baselines.semgrep.runner import (
    SemgrepFinding,
    SemgrepRunResult,
    _parse_finding,
)


class ParseFindingTests(unittest.TestCase):
    def test_parses_minimal_payload(self) -> None:
        item = {
            "check_id": "baselines.semgrep.rules.iso-a10-weak-hash",
            "path": "fixture/L06.java",
            "start": {"line": 12},
            "end": {"line": 12},
            "extra": {"message": "weak hash"},
        }
        finding = _parse_finding(item)
        self.assertEqual(
            finding,
            SemgrepFinding(
                rule_id="baselines.semgrep.rules.iso-a10-weak-hash",
                file_path="fixture/L06.java",
                start_line=12,
                end_line=12,
                message="weak hash",
            ),
        )

    def test_codegraph_violation_id_maps_well_known_rule_ids(self) -> None:
        cases = [
            ("iso-a10-weak-hash", "ISO-A.10-WEAK-HASH"),
            ("iso-a10-weak-crypto", "ISO-A.10-WEAK-CRYPTO"),
            ("iso-a10-weak-random", "ISO-A.10-WEAK-RANDOM"),
            ("iso-a8-sql-injection", "ISO-A.8-SQL-INJECTION"),
            ("iso-a8-path-traversal", "ISO-A.8-PATH-TRAVERSAL"),
            ("iso-a8-cmd-injection", "ISO-A.8-CMD-INJECTION"),
            ("iso-a8-ldap-injection", "ISO-A.8-LDAP-INJECTION"),
            ("iso-a8-xpath-injection", "ISO-A.8-XPATH-INJECTION"),
        ]
        for rule_id, expected in cases:
            with self.subTest(rule_id=rule_id):
                f = SemgrepFinding(rule_id=rule_id, file_path="", start_line=0, end_line=0, message="")
                self.assertEqual(f.codegraph_violation_id, expected)

    def test_codegraph_violation_id_returns_none_for_non_iso_rules(self) -> None:
        f = SemgrepFinding(
            rule_id="thirdparty.semgrep.rules.something",
            file_path="",
            start_line=0,
            end_line=0,
            message="",
        )
        self.assertIsNone(f.codegraph_violation_id)


class SemgrepRunResultTests(unittest.TestCase):
    def _make_findings(self) -> tuple[SemgrepFinding, ...]:
        return (
            SemgrepFinding("iso-a10-weak-hash", "a/L06.java", 12, 12, "x"),
            SemgrepFinding("iso-a8-sql-injection", "a/L12.java", 23, 23, "y"),
            SemgrepFinding("iso-a10-weak-hash", "a/L13.java", 9, 9, "z"),
        )

    def test_findings_by_file_groups_correctly(self) -> None:
        result = SemgrepRunResult(
            findings=self._make_findings(),
            rules_path=__import__("pathlib").Path("."),
            target=__import__("pathlib").Path("."),
        )
        grouped = result.findings_by_file()
        self.assertEqual(len(grouped["a/L06.java"]), 1)
        self.assertEqual(len(grouped["a/L13.java"]), 1)

    def test_findings_by_rule_groups_correctly(self) -> None:
        result = SemgrepRunResult(
            findings=self._make_findings(),
            rules_path=__import__("pathlib").Path("."),
            target=__import__("pathlib").Path("."),
        )
        grouped = result.findings_by_rule()
        self.assertEqual(len(grouped["iso-a10-weak-hash"]), 2)
        self.assertEqual(len(grouped["iso-a8-sql-injection"]), 1)


if __name__ == "__main__":
    unittest.main()
