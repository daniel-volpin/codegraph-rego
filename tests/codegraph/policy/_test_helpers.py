import unittest


class _FakeResult:
    def __init__(self, records):
        self._records = records

    def __iter__(self):
        return iter(self._records)


class _FakeSession:
    def __init__(self, records):
        self._records = records

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def run(self, _cypher, _params):
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
