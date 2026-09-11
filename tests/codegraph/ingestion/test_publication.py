from unittest.mock import Mock

import pytest

from codegraph.ingestion.service import (
    ExtractedCodeStructure,
    IngestionError,
    WorkspacePublication,
    _rollback_workspace_revision,
    create_workspace_revision,
    publish_workspace_revision,
)


def structure():
    return ExtractedCodeStructure(
        workspace_id="workspace", revision_id="revision",
        parser_backend="eclipse-jdt", parser_version="3.47.0", adapter_version="0.1.0",
        source_fingerprint="source", classpath_fingerprint=None,
    )


@pytest.mark.parametrize("previous", [[], ["old-revision"]])
def test_publication_returns_exact_predecessor(previous):
    tx = Mock()
    tx.run.return_value.single.return_value = {"previous_revisions": previous}
    result = publish_workspace_revision(tx, structure())
    assert result == WorkspacePublication("workspace", "revision", previous[0] if previous else None)
    query = tx.run.call_args.args[0]
    assert query.index("SET aw.publication_version") < query.index("OPTIONAL MATCH")


def test_repeated_staging_does_not_deactivate_an_existing_revision():
    tx = Mock()
    create_workspace_revision(tx, structure())
    query = tx.run.call_args.args[0]
    assert "ON CREATE SET wr.status = 'staged', wr.active = false" in query


def test_rollback_refuses_to_overwrite_a_newer_publisher():
    tx = Mock()
    tx.run.return_value.single.return_value = None
    with pytest.raises(IngestionError, match="refusing rollback"):
        _rollback_workspace_revision(tx, WorkspacePublication("workspace", "old-current", None))
    assert tx.run.call_args.kwargs["revision_id"] == "old-current"


def test_publication_refuses_ambiguous_previous_revisions():
    tx = Mock()
    tx.run.return_value.single.return_value = {"previous_revisions": ["first", "second"]}
    with pytest.raises(IngestionError, match="multiple active"):
        publish_workspace_revision(tx, structure())
