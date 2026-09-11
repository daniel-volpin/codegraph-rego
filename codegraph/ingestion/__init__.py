"""Ingestion package: JDT parsing, entity extraction, and Neo4j graph persistence."""

from __future__ import annotations

from codegraph.ingestion.service import (
    GRAPH_SCHEMA_VERSION,
    ExtractedCodeStructure,
    IngestionError,
    WorkspacePublication,
    ingest,
    ingest_to_neo4j,
    rollback_workspace_revision,
)

__all__ = [
    "GRAPH_SCHEMA_VERSION",
    "ExtractedCodeStructure",
    "IngestionError",
    "WorkspacePublication",
    "ingest",
    "ingest_to_neo4j",
    "rollback_workspace_revision",
]
