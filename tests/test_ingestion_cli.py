from unittest.mock import patch

import pytest

from scripts.ingestion import codebase_to_neo4j


def test_ingestion_cli_publishes_one_workspace_without_legacy_sync():
    with patch("codegraph.ingestion.service.ingest") as ingest:
        assert codebase_to_neo4j.main(["--java-root", "/source/workspace"]) == 0
    ingest.assert_called_once_with("/source/workspace", progress_callback=codebase_to_neo4j._progress)


def test_dry_run_does_not_connect_or_publish(capsys):
    with patch("codegraph.ingestion.service.ingest") as ingest:
        assert codebase_to_neo4j.main(["--java-root", "/source/workspace", "--dry-run"]) == 0
    ingest.assert_not_called()
    assert "/source/workspace" in capsys.readouterr().out


def test_removed_sync_option_is_rejected():
    with pytest.raises(SystemExit):
        codebase_to_neo4j.parse_args(["--sync"])
