"""Unit tests for AST entity extraction and provenance hashing."""

from __future__ import annotations

import unittest

from codegraph.ingestion.extraction import (
    _namespaced_key,
    _range_end_byte,
    _range_end_line,
    _range_start_byte,
    _range_start_line,
    _sha256_bytes,
    _type_display,
    _workspace_id,
)
from codegraph.java.models import SourceRangeDTO, TypeRefDTO


class TestExtractionUnit(unittest.TestCase):
    def test_sha256_bytes(self) -> None:
        self.assertEqual(
            _sha256_bytes(b"hello world"),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
        )

    def test_workspace_id_deterministic(self) -> None:
        id1 = _workspace_id("/app/project")
        id2 = _workspace_id("/app/project")
        self.assertEqual(id1, id2)
        self.assertEqual(len(id1), 16)

    def test_namespaced_key(self) -> None:
        key = _namespaced_key("ws1", "rev1", "src/Main.java", "Main#run()")
        self.assertEqual(key, "ws1@rev1:src/Main.java#Main#run()")

    def test_type_display(self) -> None:
        type_ref = TypeRefDTO(
            qualified_name="java.lang.String",
            resolution_status="resolved",
            descriptor="Ljava/lang/String;",
            binding_origin="binary",
        )
        self.assertEqual(_type_display(type_ref), "java.lang.String")

        array_ref = TypeRefDTO(
            qualified_name="byte",
            array_dimensions=1,
            resolution_status="resolved",
            descriptor="B",
            binding_origin="primitive",
        )
        self.assertEqual(_type_display(array_ref), "byte[]")

        varargs_ref = TypeRefDTO(
            qualified_name="java.lang.Object",
            varargs=True,
            resolution_status="resolved",
            descriptor="Ljava/lang/Object;",
            binding_origin="binary",
        )
        self.assertEqual(_type_display(varargs_ref), "java.lang.Object...")

    def test_range_helpers(self) -> None:
        verified_range = SourceRangeDTO(start_byte=10, end_byte=50, start_line=2, end_line=5, status="verified")
        self.assertEqual(_range_start_byte(verified_range), 10)
        self.assertEqual(_range_end_byte(verified_range), 50)
        self.assertEqual(_range_start_line(verified_range), 2)
        self.assertEqual(_range_end_line(verified_range), 5)

        unverified_range = SourceRangeDTO(
            start_byte=10,
            end_byte=50,
            start_line=2,
            end_line=5,
            status="unverified",
            reason="syntax_recovery",
        )
        self.assertIsNone(_range_start_byte(unverified_range))
        self.assertIsNone(_range_end_byte(unverified_range))
        self.assertIsNone(_range_start_line(unverified_range))
        self.assertIsNone(_range_end_line(unverified_range))


if __name__ == "__main__":
    unittest.main()
