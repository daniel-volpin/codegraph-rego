"""``_get_service`` provides one process-wide ``RemediationService``.

``functools.lru_cache(maxsize=1)`` gives tests an explicit
``cache_clear()`` for run isolation and exposes ``cache_info()`` for
hit/miss assertions.
"""

from __future__ import annotations

import unittest
from unittest.mock import patch

from codegraph.remediation import orchestration


class OrchestrationSingletonTests(unittest.TestCase):
    def setUp(self) -> None:
        orchestration._get_service.cache_clear()

    def tearDown(self) -> None:
        orchestration._get_service.cache_clear()

    def test_get_service_returns_same_instance_across_calls(self) -> None:
        with patch.object(orchestration, "RemediationService") as mock_cls:
            sentinel = object()
            mock_cls.return_value = sentinel

            first = orchestration._get_service()
            second = orchestration._get_service()
            third = orchestration._get_service()

            self.assertIs(first, sentinel)
            self.assertIs(second, sentinel)
            self.assertIs(third, sentinel)
            self.assertEqual(mock_cls.call_count, 1)

    def test_cache_clear_forces_new_instance(self) -> None:
        with patch.object(orchestration, "RemediationService") as mock_cls:
            mock_cls.side_effect = [object(), object()]

            first = orchestration._get_service()
            orchestration._get_service.cache_clear()
            second = orchestration._get_service()

            self.assertIsNot(first, second)
            self.assertEqual(mock_cls.call_count, 2)

    def test_lru_cache_is_introspectable(self) -> None:
        with patch.object(orchestration, "RemediationService", return_value=object()):
            self.assertEqual(orchestration._get_service.cache_info().currsize, 0)
            orchestration._get_service()
            self.assertEqual(orchestration._get_service.cache_info().currsize, 1)
            self.assertEqual(orchestration._get_service.cache_info().hits, 0)
            orchestration._get_service()
            self.assertEqual(orchestration._get_service.cache_info().hits, 1)


if __name__ == "__main__":
    unittest.main()
