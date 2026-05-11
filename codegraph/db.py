"""
Shared Neo4j helpers: driver factory and idempotent constraint creation.
"""

from neo4j import GraphDatabase
from codegraph.config import settings


def get_neo4j_driver():
    return GraphDatabase.driver(settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_pass))


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
