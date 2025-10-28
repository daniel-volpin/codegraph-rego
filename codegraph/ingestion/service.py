from __future__ import annotations

import os


def ingest(java_root_dir: str) -> None:
    """Ingest a Java project into Neo4j by delegating to the existing script's main().

    This sets JAVA_ROOT_DIR for the duration of the call so codebase_to_neo4j
    resolves the correct source root at runtime.
    """
    # Defer import to avoid import-time configuration surprises
    import codebase_to_neo4j as _ingest

    prev = os.environ.get("JAVA_ROOT_DIR")
    try:
        os.environ["JAVA_ROOT_DIR"] = java_root_dir
        _ingest.main()
    finally:
        if prev is not None:
            os.environ["JAVA_ROOT_DIR"] = prev
        else:
            os.environ.pop("JAVA_ROOT_DIR", None)

