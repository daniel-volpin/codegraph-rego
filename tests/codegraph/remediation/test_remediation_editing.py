import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from codegraph.ingestion.snapshots import create_source_snapshot_from_bytes, sha256_hex
from codegraph.remediation.candidate import build_candidate_overlay
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


class CandidateMethodShapeValidationTests(unittest.TestCase):
    SOURCE = (
        "class Example {\n"
        "    public void doWork(String input) {\n"
        '        System.out.println("MD5");\n'
        "    }\n"
        "}\n"
    )
    def setUp(self) -> None:
        source_bytes = self.SOURCE.encode("utf-8")
        self.baseline = create_source_snapshot_from_bytes(
            workspace_root="/workspace",
            source_path="/workspace/Example.java",
            source_bytes=source_bytes,
            method_selector="Example#doWork(String)",
            expected_source_sha256=sha256_hex(source_bytes),
        )

    def test_valid_full_method_replacement_succeeds(self) -> None:
        replacement = [
            "    public void doWork(String input) {",
            '        System.out.println("SHA-256");',
            "    }",
        ]
        overlay = build_candidate_overlay(self.baseline, "\n".join(replacement).encode("utf-8"))
        self.assertIn("SHA-256", overlay.candidate_file_source)
        self.assertIn("SHA-256", overlay.candidate_method_source)

    def test_collapsed_replacement_is_rejected(self) -> None:
        # A degenerate single-line replacement must not be spliced in silently.
        with self.assertRaises(ValueError):
            build_candidate_overlay(self.baseline, b'        System.out.println("SHA-256");')

    def test_wrong_method_name_replacement_is_rejected(self) -> None:
        replacement = [
            "    public void somethingElse(String input) {",
            "    }",
        ]
        with self.assertRaises(ValueError):
            build_candidate_overlay(self.baseline, "\n".join(replacement).encode("utf-8"))
