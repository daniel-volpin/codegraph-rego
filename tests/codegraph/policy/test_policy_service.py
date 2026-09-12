from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch


class TestPolicyService(unittest.TestCase):
    @patch("codegraph.policy.service.evaluate_policies", return_value={"violations": []})
    def test_evaluate_defaults_workspace_root_to_none(self, mock_evaluate_policies) -> None:
        from codegraph.policy.service import evaluate

        evaluate()

        self.assertIsNone(
            mock_evaluate_policies.call_args.kwargs.get("workspace_root"),
        )

    @patch("codegraph.policy.service.evaluate_policies", return_value={"violations": []})
    def test_evaluate_uses_explicit_workspace_root_when_provided(self, mock_evaluate_policies) -> None:
        from codegraph.policy.service import evaluate

        evaluate(workspace_root="/tmp/custom-upload-root")

        self.assertEqual(
            mock_evaluate_policies.call_args.kwargs["workspace_root"],
            "/tmp/custom-upload-root",
        )

    @patch("codegraph.policy.service.import_findings_from_sarif", return_value=[])
    @patch("codegraph.policy.service.shared_neo4j_driver", return_value=object())
    def test_import_sarif_normalizes_workspace_root(self, _mock_driver, mock_import) -> None:
        from codegraph.policy.service import import_sarif

        import_sarif({"version": "2.1.0"}, workspace_root="relative-workspace")

        self.assertEqual(
            mock_import.call_args.kwargs["workspace_root"],
            Path("relative-workspace").resolve().as_posix(),
        )


if __name__ == "__main__":
    unittest.main()
