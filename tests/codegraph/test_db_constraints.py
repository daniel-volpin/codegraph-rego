"""Verifies the Cypher statements that ``ensure_constraints`` issues.

Pinning the catalog of constraints/indexes prevents accidental
regressions in the graph-startup contract (a missing index silently
turns a parametric lookup into a full scan).
"""

from __future__ import annotations

import unittest

from codegraph.db import ensure_constraints


class _CapturingResult:
    def consume(self) -> None:
        return None


class _CapturingSession:
    def __init__(self, sink: list[str]) -> None:
        self._sink = sink

    def __enter__(self) -> _CapturingSession:
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False

    def run(self, statement: str, *_a, **_k):
        self._sink.append(statement)
        return _CapturingResult()


class _CapturingDriver:
    def __init__(self) -> None:
        self.statements: list[str] = []

    def session(self) -> _CapturingSession:
        return _CapturingSession(self.statements)

    def close(self) -> None:
        return None


class EnsureConstraintsTests(unittest.TestCase):
    def test_issues_expected_constraints_and_indexes(self) -> None:
        driver = _CapturingDriver()
        ensure_constraints(driver=driver)

        joined = "\n".join(driver.statements)
        # Uniqueness constraints
        self.assertIn("workspace_revision_unique", joined)
        self.assertIn("REQUIRE (wr.workspace_id, wr.revision_id) IS UNIQUE", joined)
        self.assertIn("source_file_unique", joined)
        self.assertIn("REQUIRE (sf.workspace_id, sf.revision_id, sf.relative_path) IS UNIQUE", joined)
        self.assertIn("class_type_key_unique", joined)
        self.assertIn("(c:Class)", joined)
        self.assertIn("REQUIRE c.type_key IS UNIQUE", joined)
        self.assertIn("method_key_unique", joined)
        self.assertIn("REQUIRE m.method_key IS UNIQUE", joined)
        self.assertIn("field_key_unique", joined)
        self.assertIn("REQUIRE f.field_key IS UNIQUE", joined)
        self.assertIn("call_evidence_key_unique", joined)
        self.assertIn("REQUIRE c.call_key IS UNIQUE", joined)
        self.assertIn("annotation_unique", joined)
        self.assertIn("REQUIRE a.name IS UNIQUE", joined)

        # Lookup indexes
        self.assertIn("method_full_signature_index", joined)
        self.assertIn("ON (m.full_signature)", joined)
        self.assertIn("method_display_signature_index", joined)
        self.assertIn("ON (m.signature)", joined)
        self.assertIn("method_file_path_index", joined)
        self.assertIn("ON (m.file_path)", joined)
        self.assertIn("method_workspace_revision_index", joined)
        self.assertIn("ON (m.workspace_id, m.revision_id)", joined)

    def test_every_statement_is_idempotent(self) -> None:
        driver = _CapturingDriver()
        ensure_constraints(driver=driver)
        for statement in driver.statements:
            self.assertIn("IF NOT EXISTS", statement, f"non-idempotent: {statement}")


if __name__ == "__main__":
    unittest.main()
