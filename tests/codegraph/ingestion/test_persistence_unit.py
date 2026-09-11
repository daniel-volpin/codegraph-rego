"""Unit tests for Neo4j persistence batch chunking and helper utilities."""

from __future__ import annotations

import unittest

from codegraph.ingestion.persistence import _chunked


class TestPersistenceUnit(unittest.TestCase):
    def test_chunked_splits_evenly(self) -> None:
        items = list(range(10))
        chunks = list(_chunked(items, 3))
        self.assertEqual(len(chunks), 4)
        self.assertEqual(chunks[0], [0, 1, 2])
        self.assertEqual(chunks[1], [3, 4, 5])
        self.assertEqual(chunks[2], [6, 7, 8])
        self.assertEqual(chunks[3], [9])

    def test_chunked_empty(self) -> None:
        self.assertEqual(list(_chunked([], 5)), [])

    def test_chunked_exact_size(self) -> None:
        chunks = list(_chunked([1, 2, 3], 3))
        self.assertEqual(len(chunks), 1)
        self.assertEqual(chunks[0], [1, 2, 3])


if __name__ == "__main__":
    unittest.main()
