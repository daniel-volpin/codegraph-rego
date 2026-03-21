import json
import unittest

try:
    import javalang  # noqa: F401
except ImportError:  # pragma: no cover - environment guard
    javalang = None


def _structured_apply_edits(
    *,
    original_method: str | list[str],
    replacement_method: str | list[str],
    start_line: int = 1,
    end_line: int | None = None,
) -> str:
    original_lines = original_method.splitlines() if isinstance(original_method, str) else list(original_method)
    replacement_lines = replacement_method.splitlines() if isinstance(replacement_method, str) else list(replacement_method)
    if end_line is None:
        end_line = start_line + len(original_lines) - 1
    return json.dumps(
        {
            "decision": "apply_edits",
            "edits": [
                {
                    "start_line": start_line,
                    "end_line": end_line,
                    "original_lines": original_lines,
                    "replacement_lines": replacement_lines,
                }
            ],
            "reason": "",
        }
    )


def _structured_no_fix(reason: str) -> str:
    return json.dumps(
        {
            "decision": "no_fix",
            "edits": [],
            "reason": reason,
        }
    )


@unittest.skipIf(javalang is None, "javalang not installed")
class RemediationTestBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from codegraph.remediation import service

        cls.service = service
