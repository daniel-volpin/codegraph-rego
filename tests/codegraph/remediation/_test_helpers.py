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
    replacement_lines = (
        replacement_method.splitlines() if isinstance(replacement_method, str) else list(replacement_method)
    )
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


class ViolationContextBuilder:
    def __init__(self):
        self.violation_id = "ISO-A.10-WEAK-HASH"
        self.target_method = "com.example.Foo.hash()"
        self.file_path = "Example.java"
        self.source_code = "public void hash() { }"
        self.exact_method_source = "public void hash() { }"

    def with_violation_id(self, violation_id: str) -> "ViolationContextBuilder":
        self.violation_id = violation_id
        return self

    def with_target_method(self, target_method: str) -> "ViolationContextBuilder":
        self.target_method = target_method
        return self

    def with_file_path(self, file_path: str) -> "ViolationContextBuilder":
        self.file_path = file_path
        return self

    def with_source_code(self, source_code: str) -> "ViolationContextBuilder":
        self.source_code = source_code
        return self

    def with_exact_method_source(self, exact_method_source: str) -> "ViolationContextBuilder":
        self.exact_method_source = exact_method_source
        return self

    def build(self) -> dict:
        return {
            "violation": {"violation_id": self.violation_id, "reason": "test"},
            "target_method": self.target_method,
            "file_path": self.file_path,
            "rule_id": self.violation_id,
            "evidence": {"source_code": self.source_code, "graph_context": {}, "vector_context": []},
            "catalog_entry": {"title": f"Test ({self.violation_id})"},
            "baseline_violations": [],
            "exact_method_source": self.exact_method_source,
        }


class ProposalResponseBuilder:
    def __init__(self):
        self.decision = "apply_edits"
        self.edits = []
        self.replacement_lines = []
        self.replacement_code = ""
        self.reason = ""
        self.schema_error = None
        self.raw_response_valid = True
        self.raw_output = None

    def with_no_fix(self, reason: str = "") -> "ProposalResponseBuilder":
        self.decision = "no_fix"
        self.edits = []
        self.replacement_lines = None
        self.replacement_code = None
        self.reason = reason
        self.raw_response_valid = True
        return self

    def with_error(self, schema_error: str) -> "ProposalResponseBuilder":
        self.schema_error = schema_error
        self.raw_response_valid = False
        self.raw_output = '{"decision":"apply_edits"}'
        return self

    def with_edits(
        self, start_line: int = 1, original_lines: list[str] = None, replacement_lines: list[str] = None
    ) -> "ProposalResponseBuilder":
        if original_lines is None:
            original_lines = ["public void test() {}"]
        if replacement_lines is None:
            replacement_lines = ["public void test() { /* fixed */ }"]

        self.edits = [
            {
                "start_line": start_line,
                "end_line": start_line,
                "original_lines": original_lines,
                "replacement_lines": replacement_lines,
            }
        ]
        self.replacement_lines = replacement_lines
        self.replacement_code = "\n".join(replacement_lines)
        self.raw_response_valid = True
        return self

    def build(self) -> dict:
        return {
            "decision": self.decision,
            "edits": self.edits,
            "replacement_method_lines": self.replacement_lines,
            "replacement_method_code": self.replacement_code,
            "reason": self.reason,
            "schema_error": self.schema_error,
            "generation": {
                "decision": self.decision,
                "edits": self.edits,
                "replacement_method_lines": self.replacement_lines,
                "replacement_method_code": self.replacement_code,
                "reason": self.reason or "",
                "raw_response_valid": self.raw_response_valid,
                "schema_error": self.schema_error,
            },
            "raw_output": self.raw_output,
        }


@unittest.skipIf(javalang is None, "javalang not installed")
class RemediationTestBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from codegraph.remediation import service

        cls.service = service
