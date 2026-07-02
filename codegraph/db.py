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
    """Create idempotent constraints/indexes to keep the graph consistent and faster."""
    close_driver = False
    if driver is None:
        driver = get_neo4j_driver()
        close_driver = True
    try:
        with driver.session() as session:
            # Neo4j 5.x syntax with IF NOT EXISTS
            session.run(
                "CREATE CONSTRAINT class_fqn_unique IF NOT EXISTS FOR (c:Class) REQUIRE c.fqn IS UNIQUE"
            ).consume()
            session.run(
                "CREATE CONSTRAINT method_signature_unique IF NOT EXISTS FOR (m:Method) REQUIRE m.signature IS UNIQUE"
            ).consume()
            session.run(
                "CREATE INDEX method_full_signature_index IF NOT EXISTS FOR (m:Method) ON (m.full_signature)"
            ).consume()
            # m.file_path drives the workspace-root filter at policy eval
            # time and the per-file purge in purge_workspace_entities.
            session.run(
                "CREATE INDEX method_file_path_index IF NOT EXISTS FOR (m:Method) ON (m.file_path)"
            ).consume()
            session.run(
                "CREATE CONSTRAINT field_unique IF NOT EXISTS FOR (f:Field) REQUIRE (f.class_fqn, f.name) IS UNIQUE"
            ).consume()
            session.run(
                "CREATE CONSTRAINT annotation_unique IF NOT EXISTS FOR (a:Annotation) REQUIRE a.name IS UNIQUE"
            ).consume()
    finally:
        if close_driver:
            driver.close()
