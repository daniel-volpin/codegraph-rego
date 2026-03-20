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
