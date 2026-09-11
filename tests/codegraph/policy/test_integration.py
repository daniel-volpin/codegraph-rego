import unittest

from tests.codegraph.policy._test_helpers import PolicyTestBase, _FakeDriver


class TestIntegration(PolicyTestBase):
    """Tests for policy module integration functions."""

    def test_is_test_source_path_matches_src_test_only(self) -> None:
        from codegraph.policy.runtime.bundles import is_test_source_path

        self.assertTrue(is_test_source_path("/workspace/project/src/test/java/org/example/FooTest.java"))
        self.assertTrue(is_test_source_path(r"C:\workspace\project\src\test\java\org\example\FooTest.java"))
        self.assertFalse(is_test_source_path("/workspace/project/src/main/java/org/example/Foo.java"))
        self.assertFalse(is_test_source_path(None))

    def test_fetch_methods_with_context_excludes_test_sources(self) -> None:
        from codegraph.policy.runtime.bundles import fetch_methods_with_context

        records = [
            {
                "method_key": "workspace@revision:TestController.java#method:endpoint",
                "signature": "org.example.TestController.endpoint()",
                "name": "endpoint",
                "file_path": "/workspace/project/src/test/java/org/example/TestController.java",
                "start_line": 10,
                "end_line": 12,
                "modifiers": [],
                "property_annotations": ["GetMapping"],
                "class_fqn": "org.example.TestController",
                "declaring_type_key": "workspace@revision:TestController.java#type:TestController",
                "relative_path": "src/test/java/org/example/TestController.java",
                "start_byte": 0,
                "end_byte": 10,
                "annotation_nodes": ["GetMapping"],
                "uses_fields": [],
                "calls": [],
                "callers": [],
            },
            {
                "method_key": "workspace@revision:MainController.java#method:endpoint",
                "signature": "org.example.MainController.endpoint()",
                "name": "endpoint",
                "file_path": "/workspace/project/src/main/java/org/example/MainController.java",
                "start_line": 20,
                "end_line": 24,
                "modifiers": [],
                "property_annotations": ["GetMapping"],
                "class_fqn": "org.example.MainController",
                "declaring_type_key": "workspace@revision:MainController.java#type:MainController",
                "relative_path": "src/main/java/org/example/MainController.java",
                "start_byte": 0,
                "end_byte": 10,
                "annotation_nodes": ["GetMapping"],
                "uses_fields": [],
                "calls": [],
                "callers": [],
            },
        ]

        snapshots = fetch_methods_with_context(_FakeDriver(records))

        self.assertEqual(len(snapshots), 1)
        self.assertEqual(snapshots[0]["signature"], "org.example.MainController.endpoint()")


if __name__ == "__main__":
    unittest.main()
