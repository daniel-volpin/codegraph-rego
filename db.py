"""
Shared Neo4j helpers: driver factory and idempotent constraint creation.
"""

from neo4j import GraphDatabase
from config import NEO4J_URI, NEO4J_USER, NEO4J_PASS


def get_neo4j_driver():
    return GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))


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
    finally:
        if close_driver:
            driver.close()
