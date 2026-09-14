"""Ingestion service: high-level pipeline coordinating AST extraction and Neo4j graph persistence."""

from __future__ import annotations

import os
from collections.abc import Sequence

from neo4j import GraphDatabase

from codegraph.config import settings
from codegraph.db import ensure_constraints
from codegraph.ingestion.extraction import (
    GRAPH_SCHEMA_VERSION,
    ExtractedCodeStructure,
    IngestionError,
    ProgressCallback,
    WorkspacePublication,
    _namespaced_key,
    _parse_java_source,
    _revision_id,
    _sha256_bytes,
    _validate_parsed_generation,
    _workspace_id,
    collect_code_structure,
    extract_entities_from_parsed_files,
)
from codegraph.ingestion.persistence import (
    _chunked,
    _rollback_workspace_revision,
    create_call_evidence_batch,
    create_class_batch,
    create_field_batch,
    create_method_batch,
    create_source_file_batch,
    create_workspace_revision,
    execute_write_or_raise,
    ingest_to_neo4j,
    link_calls_batch,
    link_extends_classes_batch,
    link_implements_classes_batch,
    link_method_field_use_batch,
    link_nested_classes_batch,
    publish_workspace_revision,
)
from codegraph.ingestion.persistence import (
    deactivate_other_workspaces as _deactivate_other_workspaces_tx,
)

__all__ = [
    "GRAPH_SCHEMA_VERSION",
    "ExtractedCodeStructure",
    "IngestionError",
    "ProgressCallback",
    "WorkspacePublication",
    "_chunked",
    "_namespaced_key",
    "_parse_java_source",
    "_revision_id",
    "_rollback_workspace_revision",
    "_sha256_bytes",
    "_validate_parsed_generation",
    "_workspace_id",
    "collect_code_structure",
    "create_call_evidence_batch",
    "create_class_batch",
    "create_field_batch",
    "create_method_batch",
    "create_source_file_batch",
    "create_workspace_revision",
    "execute_write_or_raise",
    "extract_entities_from_parsed_files",
    "ingest",
    "ingest_to_neo4j",
    "link_calls_batch",
    "link_extends_classes_batch",
    "link_implements_classes_batch",
    "link_method_field_use_batch",
    "link_nested_classes_batch",
    "publish_workspace_revision",
    "rollback_workspace_revision",
]


def rollback_workspace_revision(publication: WorkspacePublication) -> None:
    """Roll back the active workspace to its predecessor revision."""
    with GraphDatabase.driver(settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_pass)) as driver:
        with driver.session() as session:
            session.execute_write(_rollback_workspace_revision, publication)


def ingest(
    java_root_dir: str,
    progress_callback: ProgressCallback | None = None,
    *,
    source_roots: Sequence[str | os.PathLike[str]] | None = None,
) -> WorkspacePublication:
    java_root_dir = os.path.abspath(java_root_dir)
    if not os.path.isdir(java_root_dir):
        if progress_callback:
            progress_callback("error", f"JAVA_ROOT_DIR does not exist: {java_root_dir}", 100.0)
        raise IngestionError(f"JAVA_ROOT_DIR does not exist: {java_root_dir}")
    if progress_callback:
        progress_callback("connecting", "Checking Neo4j availability…", 10.0)
    try:
        driver = GraphDatabase.driver(settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_pass))
        with driver.session() as session:
            session.run("RETURN 1 AS ok").consume()
        driver.close()
    except Exception as exc:
        if progress_callback:
            progress_callback("error", f"Neo4j connection failed: {exc}", 100.0)
        raise IngestionError(f"Neo4j connection failed: {exc}") from exc
    ensure_constraints()
    structure = collect_code_structure(java_root_dir, progress_callback=progress_callback, source_roots=source_roots)
    publication = ingest_to_neo4j(structure, progress_callback=progress_callback)
    if progress_callback:
        progress_callback("ingesting", "Ingestion complete.", 90.0)
    return publication


def deactivate_other_workspaces(workspace_id: str) -> list[str]:
    """Make ``workspace_id`` the only active workspace. Returns the ones dropped."""
    with GraphDatabase.driver(settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_pass)) as driver:
        with driver.session() as session:
            return session.execute_write(_deactivate_other_workspaces_tx, workspace_id)

