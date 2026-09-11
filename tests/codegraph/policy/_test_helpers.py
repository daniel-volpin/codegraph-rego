import tempfile
import unittest
from pathlib import Path


class _FakeResult:
    def __init__(self, records):
        self._records = records

    def __iter__(self):
        return iter(self._records)

    def single(self):
        return self._records[0] if self._records else None


class _FakeSession:
    def __init__(self, records):
        self._records = records

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def run(self, _cypher, _params=None, **_kwargs):
        return _FakeResult(self._records)


class _FakeDriver:
    def __init__(self, records):
        self._records = records

    def session(self):
        return _FakeSession(self._records)


class BundleBuilder:
    """Builder for creating test bundles with sensible defaults."""

    def __init__(self):
        self.target_method = ""
        self.file_path = ""
        self.source_code = ""
        self.graph_context = {"annotations": [], "uses_fields": [], "calls": [], "callers": []}
        self.analysis_flags = None
        self.helper_summaries = None
        self.vector_context = []
        self.start_line = None
        self.end_line = None

    def with_target_method(self, target_method):
        self.target_method = target_method
        return self

    def with_file_path(self, file_path):
        self.file_path = file_path
        return self

    def with_source_code(self, source_code):
        self.source_code = source_code
        return self

    def with_analysis_flags(self, flags):
        self.analysis_flags = flags
        return self

    def with_helper_summaries(self, summaries):
        self.helper_summaries = summaries
        return self

    def with_graph_context(self, annotations=None, uses_fields=None, calls=None, callers=None):
        self.graph_context = {
            "annotations": annotations or [],
            "uses_fields": uses_fields or [],
            "calls": calls or [],
            "callers": callers or [],
        }
        return self

    def with_annotation(self, *annotations):
        self.graph_context["annotations"] = list(annotations)
        return self

    def with_vector_context(self, vector_context):
        self.vector_context = vector_context
        return self

    def with_line_numbers(self, start_line, end_line):
        self.start_line = start_line
        self.end_line = end_line
        return self

    def build(self):
        bundle = {
            "target_method": self.target_method,
            "file_path": self.file_path,
            "source_code": self.source_code,
            "graph_context": self.graph_context,
            "vector_context": self.vector_context,
        }
        if self.analysis_flags is not None:
            bundle["analysis_flags"] = self.analysis_flags
        if self.helper_summaries is not None:
            bundle["helper_summaries"] = self.helper_summaries
        if self.start_line is not None:
            bundle["start_line"] = self.start_line
        if self.end_line is not None:
            bundle["end_line"] = self.end_line
        return bundle


class PolicyTestBase(unittest.TestCase):
    """Base class for policy module tests."""

    @staticmethod
    def _normalized_violation_ids(raw_output) -> set[str]:
        from codegraph.policy.integration import normalize_violation_payload

        if isinstance(raw_output, dict):
            payloads = list(raw_output.keys())
        else:
            payloads = list(raw_output)
        normalized = [normalize_violation_payload(item) for item in payloads]
        return {item.get("violation_id") for item in normalized if item}


# ---------------------------------------------------------------------------
# Common Java source bodies used across DirectCallSummaryBuilder tests
# ---------------------------------------------------------------------------

_JAVA_TAINTED_PASSTHROUGH = [
    "class Helper {",
    "  private String doSomething(String param) {",
    "    return param;",
    "  }",
    "}",
]

_JAVA_SAFE_CONSTANT = [
    "class Helper {",
    "  private String doSomething(String param) {",
    '    String bar = "safe!";',
    "    return bar;",
    "  }",
    "}",
]

_JAVA_SAFE_RETURN_LITERAL = [
    "class Helper {",
    "  private String doSomething(String param) {",
    '    return "safe!";',
    "  }",
    "}",
]

_JAVA_SAFE_RETURN_STRING = [
    "class Helper {",
    "  private String doSomething(String param) {",
    '    return "safe";',
    "  }",
    "}",
]

_JAVA_SAFE_CONDITIONAL = [
    "class Helper {",
    "  private String doSomething(String param) {",
    "    int num = 106;",
    '    String bar = (7 * 18) + num > 200 ? "This_should_always_happen" : param;',
    "    return bar;",
    "  }",
    "}",
]

_JAVA_TAINTED_INDIRECTION = [
    "class Helper {",
    "  private String doSomething(String param) {",
    "    String bar = param;",
    "    return bar;",
    "  }",
    "}",
]

_DEFAULT_SIG = "org.example.Controller.doSomething(java.lang.String)"
_DEFAULT_FQN = "org.example.Controller"


class DirectCallTestBase(unittest.TestCase):
    """Base class for DirectCallSummaryBuilder tests.

    Provides convenience helpers that eliminate the repeated 20-30 line
    boilerplate pattern of: write temp Java file → build method dicts →
    call builder.build().
    """

    def _build_summaries(
        self,
        current_source: str,
        java_body_lines: list[str],
        *,
        sig: str = _DEFAULT_SIG,
        fqn: str = _DEFAULT_FQN,
        name: str = "doSomething",
        start_line: int = 2,
        end_line: int = 3,
        extra_snapshot_calls: list[str] | None = None,
    ) -> dict:
        """Build helper summaries for a callee method defined in a temp Java file."""
        from codegraph.policy.helper_summaries import DirectCallSummaryBuilder

        builder = DirectCallSummaryBuilder()
        with tempfile.TemporaryDirectory() as tmpdir:
            callee_path = Path(tmpdir) / "Helper.java"
            callee_path.write_text("\n".join(java_body_lines), encoding="utf-8")
            byte_length = len(callee_path.read_bytes())
            method_snapshot = {
                "class_fqn": fqn,
                "calls": [sig] + (extra_snapshot_calls or []),
            }
            method_index = {
                sig: {
                    "signature": sig,
                    "class_fqn": fqn,
                    "name": name,
                    "file_path": callee_path.as_posix(),
                    "start_byte": 0,
                    "end_byte": byte_length,
                    "start_line": start_line,
                    "end_line": end_line,
                }
            }
            return builder.build(
                current_source=current_source,
                method_snapshot=method_snapshot,
                method_index=method_index,
            )

    def _build_summaries_no_helper(
        self,
        current_source: str,
        fqn: str = _DEFAULT_FQN,
    ) -> dict:
        """Build summaries without a callee method (inline/constant calls only)."""
        from codegraph.policy.helper_summaries import DirectCallSummaryBuilder

        builder = DirectCallSummaryBuilder()
        return builder.build(
            current_source=current_source,
            method_snapshot={"class_fqn": fqn, "calls": []},
            method_index={},
        )
