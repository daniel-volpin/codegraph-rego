import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from codegraph.ingestion.service import IngestionError, ingest, ingest_to_neo4j


class IngestionServiceTests(unittest.TestCase):
    @patch("codegraph.ingestion.service.GraphDatabase.driver")
    def test_ingest_raises_when_neo4j_unavailable(self, mock_driver) -> None:
        mock_driver.side_effect = RuntimeError("neo4j down")

        with TemporaryDirectory() as tmp_dir:
            java_root = Path(tmp_dir) / "src" / "main" / "java"
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

        method = SimpleNamespace(signature="com.example.Test.run()", annotations=[])
        field = SimpleNamespace(
            class_fqn="com.example.Test",
            name="value",
            type="String",
            modifiers=[],
            annotations=[],
            file_path="/tmp/Test.java",
            start_line=1,
            end_line=1,
        )

        with patch("codegraph.ingestion.service.GraphDatabase.driver", return_value=_Driver()):
            with self.assertRaises(IngestionError) as ctx:
                ingest_to_neo4j(
                    methods=[method],
                    nested_relations=[],
                    extends_relations=[],
                    implements_relations=[],
                    uses_relations=[],
                    depends_on_relations=[],
                    calls_relations=[],
                    field_entities=[field],
                    method_field_relations=[],
                )

        self.assertIn("Neo4j write failed during field persistence", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
