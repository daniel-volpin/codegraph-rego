"""Unit tests for graph query helpers and snapshot projection."""

from __future__ import annotations

import unittest

from codegraph.policy.runtime.graph_queries import (
    _combined_annotations,
    _snapshot_from_record,
    _sorted_non_empty_strings,
    _sorted_used_fields,
    is_test_source_path,
)


class TestGraphQueries(unittest.TestCase):
    def test_is_test_source_path(self) -> None:
        self.assertTrue(is_test_source_path("/app/src/test/java/com/acme/Test.java"))
        self.assertTrue(is_test_source_path("src/test/java/com/acme/Test.java"))
        self.assertFalse(is_test_source_path("/app/src/main/java/com/acme/Service.java"))
        self.assertFalse(is_test_source_path(None))

    def test_sorted_non_empty_strings(self) -> None:
        self.assertEqual(_sorted_non_empty_strings(["b", "", "a", None, "c"]), ["a", "b", "c"])

    def test_sorted_used_fields(self) -> None:
        fields = [
            {"name": "fieldB", "type": "String"},
            {"name": None},
            {"name": "fieldA", "type": "int"},
        ]
        sorted_fields = _sorted_used_fields(fields)
        self.assertEqual(len(sorted_fields), 2)
        self.assertEqual(sorted_fields[0]["name"], "fieldA")
        self.assertEqual(sorted_fields[1]["name"], "fieldB")

    def test_combined_annotations(self) -> None:
        props = ["@Deprecated", "@Override"]
        nodes = ["@Override", "@Transactional"]
        combined = _combined_annotations(props, nodes)
        self.assertEqual(combined, ["@Deprecated", "@Override", "@Transactional"])

    def test_snapshot_from_record_filters_test_files(self) -> None:
        record = {
            "method_key": "ws@rev:Test.java#test()",
            "signature": "test()",
            "file_path": "/app/src/test/java/com/acme/Test.java",
        }
        self.assertIsNone(_snapshot_from_record(record))

    def test_snapshot_from_record_valid_main_file(self) -> None:
        record = {
            "method_key": "ws@rev:Service.java#doSomething()",
            "signature": "doSomething()",
            "name": "doSomething",
            "file_path": "/app/src/main/java/com/acme/Service.java",
            "start_line": 10,
            "end_line": 20,
            "start_byte": 100,
            "end_byte": 250,
            "property_annotations": ["@Service"],
            "annotation_nodes": [],
            "uses_fields": [],
            "calls": ["helper()"],
            "call_evidence": [],
            "callers": [],
            "workspace_id": "ws",
            "revision_id": "rev",
            "parser_backend": "eclipse-jdt",
            "parser_version": "3.47.0",
            "source_sha256": "abc123",
            "range_status": "verified",
        }
        snapshot = _snapshot_from_record(record)
        self.assertIsNotNone(snapshot)
        assert snapshot is not None
        self.assertEqual(snapshot["method_key"], "ws@rev:Service.java#doSomething()")
        self.assertEqual(snapshot["annotations"], ["@Service"])


if __name__ == "__main__":
    unittest.main()
