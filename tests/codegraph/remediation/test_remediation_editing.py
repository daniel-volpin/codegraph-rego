import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from codegraph.remediation.editing import resolve_file_path


class RemediationEditingTests(unittest.TestCase):
    def test_resolve_file_path_finds_workspace_relative_multi_root_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            workspace = Path(tmp_dir) / "uploaded_code"
            source_file = workspace / "module-a" / "src" / "main" / "java" / "com" / "example" / "App.java"
            source_file.parent.mkdir(parents=True)
            source_file.write_text("class App {}", encoding="utf-8")

            with patch("codegraph.remediation.editing.settings.upload_dir", str(workspace)):
                resolved = resolve_file_path("module-a/src/main/java/com/example/App.java")

            self.assertEqual(resolved, source_file)

    def test_resolve_file_path_prefers_absolute_file_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            source_file = Path(tmp_dir) / "App.java"
            source_file.write_text("class App {}", encoding="utf-8")

            resolved = resolve_file_path(str(source_file))

            self.assertEqual(resolved, source_file)


if __name__ == "__main__":
    unittest.main()


class ReplaceMethodShapeValidationTests(unittest.TestCase):
    SOURCE = (
        "class Example {\n"
        "    public void doWork(String input) {\n"
        '        System.out.println("MD5");\n'
        "    }\n"
        "}\n"
    )
    TARGET = "com.example.Example.doWork(String)"

    def test_valid_full_method_replacement_succeeds(self) -> None:
        from codegraph.remediation.editing import replace_method_in_source

        replacement = [
            "    public void doWork(String input) {",
            '        System.out.println("SHA-256");',
            "    }",
        ]
        new_source, _, updated = replace_method_in_source(self.SOURCE, replacement, self.TARGET)
        self.assertIn("SHA-256", new_source)
        self.assertIn("SHA-256", updated)

    def test_collapsed_replacement_is_rejected(self) -> None:
        from codegraph.remediation.editing import replace_method_in_source

        # A degenerate single-line replacement must not be spliced in silently.
        with self.assertRaises(ValueError):
            replace_method_in_source(self.SOURCE, ['        System.out.println("SHA-256");'], self.TARGET)

    def test_wrong_method_name_replacement_is_rejected(self) -> None:
        from codegraph.remediation.editing import replace_method_in_source

        replacement = [
            "    public void somethingElse(String input) {",
            "    }",
        ]
        with self.assertRaises(ValueError):
            replace_method_in_source(self.SOURCE, replacement, self.TARGET)
