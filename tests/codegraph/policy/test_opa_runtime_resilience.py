"""Resilience regression tests for the OPA subprocess boundary.

These do not require the ``opa`` binary: ``subprocess.run`` is patched, so they
exercise the timeout / failure contract in isolation.
"""

import subprocess
import unittest
from unittest.mock import patch

from codegraph.policy.runtime import opa as runtime_opa


class TestOpaTimeoutContract(unittest.TestCase):
    def test_evaluate_bundle_converts_timeout_to_runtime_error(self) -> None:
        bundle = {"target_method": "com.example.Foo.bar()", "source_code": ""}
        with patch(
            "codegraph.policy.runtime.opa.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="opa", timeout=120),
        ):
            with self.assertRaises(RuntimeError) as ctx:
                runtime_opa.evaluate_bundle(bundle)
        self.assertIn("timed out", str(ctx.exception))

    def test_evaluate_package_root_converts_timeout_to_runtime_error(self) -> None:
        bundle = {"target_method": "com.example.Foo.bar()", "source_code": ""}
        with patch(
            "codegraph.policy.runtime.opa.subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="opa", timeout=120),
        ):
            with self.assertRaises(RuntimeError) as ctx:
                runtime_opa.evaluate_package_root(bundle)
        self.assertIn("timed out", str(ctx.exception))

    def test_evaluate_bundle_passes_timeout_to_subprocess(self) -> None:
        bundle = {"target_method": "m", "source_code": ""}

        class _Proc:
            returncode = 0
            stdout = '{"result": []}'
            stderr = ""

        with patch("codegraph.policy.runtime.opa.subprocess.run", return_value=_Proc()) as mock_run:
            runtime_opa.evaluate_bundle(bundle)
        _, kwargs = mock_run.call_args
        self.assertIn("timeout", kwargs)
        self.assertGreater(kwargs["timeout"], 0)

    def test_timeout_seconds_env_override(self) -> None:
        with patch.dict("os.environ", {"CODEGRAPH_OPA_TIMEOUT": "7.5"}):
            self.assertEqual(runtime_opa._opa_timeout_seconds(), 7.5)
        with patch.dict("os.environ", {"CODEGRAPH_OPA_TIMEOUT": "not-a-number"}):
            self.assertEqual(runtime_opa._opa_timeout_seconds(), 120.0)
        with patch.dict("os.environ", {"CODEGRAPH_OPA_TIMEOUT": "-5"}):
            self.assertEqual(runtime_opa._opa_timeout_seconds(), 120.0)


if __name__ == "__main__":
    unittest.main()
