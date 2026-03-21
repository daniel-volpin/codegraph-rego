import unittest

from tests.codegraph.policy._test_helpers import PolicyTestBase, _FakeDriver


class TestIntegration(PolicyTestBase):
    """Tests for policy module integration functions."""

    def test_is_test_source_path_matches_src_test_only(self) -> None:
        from codegraph.policy.integration import _is_test_source_path

        self.assertTrue(_is_test_source_path("/workspace/project/src/test/java/org/example/FooTest.java"))
        self.assertTrue(_is_test_source_path(r"C:\workspace\project\src\test\java\org\example\FooTest.java"))
        self.assertFalse(_is_test_source_path("/workspace/project/src/main/java/org/example/Foo.java"))
        self.assertFalse(_is_test_source_path(None))

    def test_fetch_methods_with_context_excludes_test_sources(self) -> None:
        from codegraph.policy.integration import _fetch_methods_with_context

        records = [
            {
                "signature": "org.example.TestController.endpoint()",
                "name": "endpoint",
                "file_path": "/workspace/project/src/test/java/org/example/TestController.java",
                "start_line": 10,
                "end_line": 12,
                "modifiers": [],
                "property_annotations": ["GetMapping"],
                "class_fqn": "org.example.TestController",
                "annotation_nodes": ["GetMapping"],
                "uses_fields": [],
                "calls": [],
                "callers": [],
            },
            {
                "signature": "org.example.MainController.endpoint()",
                "name": "endpoint",
                "file_path": "/workspace/project/src/main/java/org/example/MainController.java",
                "start_line": 20,
                "end_line": 24,
                "modifiers": [],
                "property_annotations": ["GetMapping"],
                "class_fqn": "org.example.MainController",
                "annotation_nodes": ["GetMapping"],
                "uses_fields": [],
                "calls": [],
                "callers": [],
            },
        ]

        snapshots = _fetch_methods_with_context(_FakeDriver(records))

        self.assertEqual(len(snapshots), 1)
        self.assertEqual(snapshots[0]["signature"], "org.example.MainController.endpoint()")


if __name__ == "__main__":
    unittest.main()
