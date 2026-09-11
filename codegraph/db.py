"""
Shared Neo4j helpers: driver factory, process-wide shared driver, and
idempotent constraint creation.

Lifecycle ownership: long-lived server paths (API routers, policy runtime,
search) use ``shared_neo4j_driver`` and must NOT close it — the app lifespan
(or atexit, for scripts) closes it once. One-shot evaluation scripts that
own their whole process lifetime keep using ``get_neo4j_driver`` and close
it themselves.
"""

import atexit
import threading

from neo4j import GraphDatabase

from codegraph.config import settings

_SHARED_DRIVER = None
_SHARED_DRIVER_LOCK = threading.Lock()


def get_neo4j_driver():
    return GraphDatabase.driver(settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_pass))


def shared_neo4j_driver():
    """Process-wide driver (one connection pool). Callers must not close it."""
    global _SHARED_DRIVER
    with _SHARED_DRIVER_LOCK:
        if _SHARED_DRIVER is None:
            _SHARED_DRIVER = get_neo4j_driver()
            atexit.register(close_shared_neo4j_driver)
    return _SHARED_DRIVER


def close_shared_neo4j_driver() -> None:
    global _SHARED_DRIVER
    with _SHARED_DRIVER_LOCK:
        if _SHARED_DRIVER is not None:
            _SHARED_DRIVER.close()
            _SHARED_DRIVER = None


def ensure_constraints(driver=None):
    """Create idempotent constraints/indexes for the JDT identity graph."""
    close_driver = False
    if driver is None:
        driver = get_neo4j_driver()
        close_driver = True
    try:
        with driver.session() as session:
            session.run(
                "CREATE CONSTRAINT workspace_revision_unique IF NOT EXISTS "
                "FOR (wr:WorkspaceRevision) REQUIRE (wr.workspace_id, wr.revision_id) IS UNIQUE"
            ).consume()
            session.run(
                "CREATE CONSTRAINT active_workspace_unique IF NOT EXISTS "
                "FOR (aw:ActiveWorkspace) REQUIRE aw.workspace_id IS UNIQUE"
            ).consume()
            session.run(
                "CREATE CONSTRAINT source_file_unique IF NOT EXISTS "
                "FOR (sf:SourceFile) REQUIRE (sf.workspace_id, sf.revision_id, sf.relative_path) IS UNIQUE"
            ).consume()
            session.run(
                "CREATE CONSTRAINT class_type_key_unique IF NOT EXISTS FOR (c:Class) REQUIRE c.type_key IS UNIQUE"
            ).consume()
            session.run(
                "CREATE CONSTRAINT method_key_unique IF NOT EXISTS FOR (m:Method) REQUIRE m.method_key IS UNIQUE"
            ).consume()
            session.run(
                "CREATE CONSTRAINT field_key_unique IF NOT EXISTS FOR (f:Field) REQUIRE f.field_key IS UNIQUE"
            ).consume()
            session.run(
                "CREATE CONSTRAINT call_evidence_key_unique IF NOT EXISTS "
                "FOR (c:CallEvidence) REQUIRE c.call_key IS UNIQUE"
            ).consume()
            session.run(
                "CREATE INDEX method_full_signature_index IF NOT EXISTS FOR (m:Method) ON (m.full_signature)"
            ).consume()
            session.run(
                "CREATE INDEX method_display_signature_index IF NOT EXISTS FOR (m:Method) ON (m.signature)"
            ).consume()
            session.run(
                "CREATE INDEX method_file_path_index IF NOT EXISTS FOR (m:Method) ON (m.file_path)"
            ).consume()
            session.run(
                "CREATE INDEX method_workspace_revision_index IF NOT EXISTS "
                "FOR (m:Method) ON (m.workspace_id, m.revision_id)"
            ).consume()
            session.run(
                "CREATE CONSTRAINT annotation_unique IF NOT EXISTS FOR (a:Annotation) REQUIRE a.name IS UNIQUE"
            ).consume()
    finally:
        if close_driver:
            driver.close()
