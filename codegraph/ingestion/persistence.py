"""Neo4j Persistence Batch Writers for CodeGraph Ingestion."""

from __future__ import annotations

import logging

from neo4j import GraphDatabase

from codegraph.config import settings
from codegraph.ingestion.extraction import (
    ExtractedCodeStructure,
    IngestionError,
    ProgressCallback,
    WorkspacePublication,
)
from codegraph.ingestion.persistence_batches import (
    create_call_evidence_batch,
    create_class_batch,
    create_config_property_batch,
    create_field_batch,
    create_method_batch,
    create_source_file_batch,
    create_workspace_revision,
    link_calls_batch,
    link_extends_classes_batch,
    link_implements_classes_batch,
    link_method_field_use_batch,
    link_nested_classes_batch,
)

LOGGER = logging.getLogger(__name__)

__all__ = [
    "create_call_evidence_batch",
    "create_class_batch",
    "create_config_property_batch",
    "create_field_batch",
    "create_method_batch",
    "create_source_file_batch",
    "create_workspace_revision",
    "deactivate_other_workspaces",
    "execute_write_or_raise",
    "ingest_to_neo4j",
    "link_calls_batch",
    "link_extends_classes_batch",
    "link_implements_classes_batch",
    "link_method_field_use_batch",
    "link_nested_classes_batch",
    "publish_workspace_revision",
]


def _chunked(values, size: int):
    for index in range(0, len(values), size):
        yield values[index : index + size]


def deactivate_other_workspaces(tx, workspace_id: str) -> list[str]:
    """Drop the active pointer of every workspace except ``workspace_id``."""
    record = tx.run(
        """
        MATCH (aw:ActiveWorkspace)
        WHERE aw.workspace_id <> $workspace_id
        OPTIONAL MATCH (aw)-[link:ACTIVE_REVISION]->(:WorkspaceRevision)
        WITH collect(DISTINCT aw.workspace_id) AS deactivated,
             collect(DISTINCT aw) AS pointers,
             collect(link) AS links
        FOREACH (l IN links | DELETE l)
        FOREACH (p IN pointers | DELETE p)
        RETURN deactivated
        """,
        workspace_id=workspace_id,
    ).single()
    return list(record["deactivated"]) if record and record.get("deactivated") else []


def publish_workspace_revision(tx, structure: ExtractedCodeStructure) -> WorkspacePublication:
    record = tx.run(
        """
        MERGE (aw:ActiveWorkspace {workspace_id: $workspace_id})
        SET aw.publication_version = coalesce(aw.publication_version, 0) + 1
        WITH aw
        MATCH (wr:WorkspaceRevision {workspace_id: $workspace_id, revision_id: $revision_id})
        OPTIONAL MATCH (aw)-[old:ACTIVE_REVISION]->(previous:WorkspaceRevision)
        WITH aw, wr, collect(old) AS old_links, collect(previous.revision_id) AS previous_revisions
        FOREACH (old IN old_links | DELETE old)
        SET wr.status = 'active',
            wr.active = true,
            wr.published_at = datetime()
        MERGE (aw)-[:ACTIVE_REVISION]->(wr)
        RETURN previous_revisions
        """,
        workspace_id=structure.workspace_id,
        revision_id=structure.revision_id,
    ).single()
    if record is None or not isinstance(record.get("previous_revisions"), list):
        raise IngestionError("Workspace publication did not return its previous revision.")
    previous = record["previous_revisions"]
    if len(previous) > 1:
        raise IngestionError("Workspace has multiple active revisions; refusing publication.")
    return WorkspacePublication(structure.workspace_id, structure.revision_id, previous[0] if previous else None)


def _rollback_workspace_revision(tx, publication: WorkspacePublication) -> None:
    record = tx.run(
        """
        MATCH (aw:ActiveWorkspace {workspace_id: $workspace_id})
        SET aw.publication_version = coalesce(aw.publication_version, 0) + 1
        WITH aw
        MATCH (aw)-[current:ACTIVE_REVISION]->(wr:WorkspaceRevision {revision_id: $revision_id})
        OPTIONAL MATCH (previous:WorkspaceRevision {workspace_id: $workspace_id})
        WHERE previous.revision_id = $previous_revision_id
        WITH aw, current, wr, previous
        WHERE $previous_revision_id IS NULL OR previous IS NOT NULL
        DELETE current
        SET wr.active = false, wr.status = 'staged'
        FOREACH (prior IN CASE WHEN previous IS NULL THEN [] ELSE [previous] END |
            MERGE (aw)-[:ACTIVE_REVISION]->(prior)
            SET prior.active = true, prior.status = 'active'
        )
        RETURN aw.workspace_id AS workspace_id
        """,
        workspace_id=publication.workspace_id,
        revision_id=publication.revision_id,
        previous_revision_id=publication.previous_revision_id,
    ).single()
    if record is None:
        raise IngestionError("Workspace revision changed or its predecessor is unavailable; refusing rollback.")


def execute_write_or_raise(session, label: str, func, *args, **kwargs):
    try:
        return session.execute_write(func, *args, **kwargs)
    except IngestionError:
        raise
    except Exception as exc:
        LOGGER.error("Neo4j write failed during %s: %s", label, exc)
        raise IngestionError(f"Neo4j write failed during {label}: {exc}") from exc


def ingest_to_neo4j(
    structure: ExtractedCodeStructure,
    progress_callback: ProgressCallback | None = None,
) -> WorkspacePublication:
    driver = GraphDatabase.driver(settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_pass))
    try:
        with driver.session() as session:
            if progress_callback:
                progress_callback("ingesting", "Persisting parser generation to Neo4j…", 60.0)
            execute_write_or_raise(session, "workspace revision persistence", create_workspace_revision, structure)
            for chunk in _chunked(structure.source_files, 5000):
                execute_write_or_raise(session, "source file persistence", create_source_file_batch, tuple(chunk))
            for chunk in _chunked(structure.classes, 5000):
                execute_write_or_raise(session, "class persistence", create_class_batch, tuple(chunk))
            for chunk in _chunked(structure.methods, 5000):
                execute_write_or_raise(session, "method persistence", create_method_batch, tuple(chunk))
            for chunk in _chunked(structure.fields, 5000):
                execute_write_or_raise(session, "field persistence", create_field_batch, tuple(chunk))
            if structure.nested_relations:
                for chunk in _chunked(structure.nested_relations, 5000):
                    execute_write_or_raise(session, "nested class relations", link_nested_classes_batch, tuple(chunk))
            if structure.extends_relations:
                for chunk in _chunked(structure.extends_relations, 5000):
                    execute_write_or_raise(session, "class inheritance relations", link_extends_classes_batch, tuple(chunk))
            if structure.implements_relations:
                for chunk in _chunked(structure.implements_relations, 5000):
                    execute_write_or_raise(session, "class interface relations", link_implements_classes_batch, tuple(chunk))
            if structure.calls_relations:
                for chunk in _chunked(structure.calls_relations, 5000):
                    execute_write_or_raise(session, "method calls relations", link_calls_batch, tuple(chunk))
            if structure.call_evidence:
                for chunk in _chunked(structure.call_evidence, 5000):
                    execute_write_or_raise(session, "unresolved call evidence", create_call_evidence_batch, tuple(chunk))
            if structure.config_properties:
                for chunk in _chunked(structure.config_properties, 5000):
                    execute_write_or_raise(session, "configuration properties", create_config_property_batch, tuple(chunk))
            if structure.method_field_relations:
                for chunk in _chunked(structure.method_field_relations, 5000):
                    execute_write_or_raise(session, "field usage relations", link_method_field_use_batch, tuple(chunk))
            if progress_callback:
                progress_callback("ingesting", "Publishing active workspace revision…", 80.0)
            publication = execute_write_or_raise(session, "workspace publication", publish_workspace_revision, structure)
            return publication
    finally:
        driver.close()
