import shutil
import unittest
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from inspect import signature
from pathlib import Path
from unittest.mock import patch

from codegraph.ingestion.service import ExtractedCodeStructure, IngestionError, ingest, ingest_to_neo4j

_TEST_WORK_ROOT = Path(__file__).resolve().parents[3] / ".copilot-ingestion-service-test-work"


@contextmanager
def workspace_case() -> Iterator[Path]:
    _TEST_WORK_ROOT.mkdir(exist_ok=True)
    case_dir = _TEST_WORK_ROOT / uuid.uuid4().hex
    case_dir.mkdir()
    try:
        yield case_dir
    finally:
        shutil.rmtree(case_dir, ignore_errors=True)
        try:
            _TEST_WORK_ROOT.rmdir()
        except OSError:
            pass


class IngestionServiceTests(unittest.TestCase):
    @patch("codegraph.ingestion.service.GraphDatabase.driver")
    def test_ingest_raises_when_neo4j_unavailable(self, mock_driver) -> None:
        mock_driver.side_effect = RuntimeError("neo4j down")

        with workspace_case() as case_dir:
            java_root = case_dir / "src" / "main" / "java"
            java_root.mkdir(parents=True)

            with self.assertRaises(IngestionError) as ctx:
                ingest(java_root.as_posix())

            self.assertIn("Neo4j connection failed", str(ctx.exception))

    def test_ingest_raises_when_java_root_missing(self) -> None:
        with self.assertRaises(IngestionError) as ctx:
            ingest("/definitely/missing/java/root")

        self.assertIn("JAVA_ROOT_DIR does not exist", str(ctx.exception))

    def test_ingest_to_neo4j_raises_when_any_write_fails(self) -> None:
        class _Session:
            def __init__(self) -> None:
                self.calls = 0

            def execute_write(self, func, *args) -> None:
                self.calls += 1
                if self.calls == 2:
                    raise RuntimeError("boom")

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

        class _Driver:
            def __init__(self) -> None:
                self.session_obj = _Session()

            def session(self):
                return self.session_obj

            def close(self) -> None:
                pass

        structure = ExtractedCodeStructure(
            workspace_id="workspace",
            revision_id="revision",
            parser_backend="eclipse-jdt",
            parser_version="3.47.0",
            adapter_version="0.1.0",
            source_fingerprint="source",
            classpath_fingerprint=None,
            source_files=(
                {
                    "workspace_id": "workspace",
                    "revision_id": "revision",
                    "relative_path": "Test.java",
                    "file_path": "Test.java",
                    "source_sha256": "e" * 64,
                    "source_byte_length": 1,
                    "coverage": "complete",
                    "parser_backend": "eclipse-jdt",
                    "parser_version": "3.47.0",
                    "adapter_version": "0.1.0",
                    "diagnostics": [],
                },
            ),
        )

        with patch("codegraph.ingestion.service.GraphDatabase.driver", return_value=_Driver()):
            with self.assertRaises(IngestionError) as ctx:
                ingest_to_neo4j(structure)

        self.assertIn("Neo4j write failed during source file persistence", str(ctx.exception))

    def test_ingest_to_neo4j_publishes_active_revision_after_writes(self) -> None:
        calls: list[str] = []

        class _Session:
            def execute_write(self, func, *args) -> None:
                calls.append(func.__name__)

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

        class _Driver:
            def session(self):
                return _Session()

            def close(self) -> None:
                pass

        structure = ExtractedCodeStructure(
            workspace_id="workspace",
            revision_id="revision",
            parser_backend="eclipse-jdt",
            parser_version="3.47.0",
            adapter_version="0.1.0",
            source_fingerprint="source",
            classpath_fingerprint=None,
        )

        with patch("codegraph.ingestion.service.GraphDatabase.driver", return_value=_Driver()):
            ingest_to_neo4j(structure)

        self.assertEqual(calls, ["create_workspace_revision", "publish_workspace_revision"])

class IngestionPublicContractTests(unittest.TestCase):
    def test_ingest_public_contract_is_workspace_revision_publish(self) -> None:
        self.assertEqual(
            list(signature(ingest).parameters),
            ["java_root_dir", "progress_callback", "source_roots"],
        )


if __name__ == "__main__":
    unittest.main()
