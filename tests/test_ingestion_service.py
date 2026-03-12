import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from codegraph.ingestion.service import IngestionError, ingest


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


if __name__ == "__main__":
    unittest.main()
