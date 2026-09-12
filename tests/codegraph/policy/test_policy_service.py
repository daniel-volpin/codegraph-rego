from __future__ import annotations

import os
import unittest
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


if __name__ == "__main__":
    unittest.main()
