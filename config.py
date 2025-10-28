"""
Central configuration for the project. Values can be overridden via environment variables.
If `python-dotenv` is installed and a `.env` file is present, it will be loaded automatically.
"""

import os
import os.path as _p

try:
    from dotenv import load_dotenv  # type: ignore
    load_dotenv()
except Exception:
    # Optional dependency; ignore if not installed
    pass


# General paths
INDEX_DIR = os.getenv("INDEX_DIR", "index")
FAISS_INDEX_PATH = _p.join(INDEX_DIR, "code_embeddings.index")
# Legacy name kept for backward compatibility
SIGNATURE_MAP_PATH = _p.join(INDEX_DIR, "embedding_signature_map.json")
# Preferred full-signature map
SIGNATURE_MAP_PATH_FULL = _p.join(INDEX_DIR, "embedding_full_signature_map.json")
EMBEDDING_METADATA_PATH = _p.join(INDEX_DIR, "embedding_metadata.json")

# Model
EMBEDDING_MODEL_NAME = os.getenv("EMBEDDING_MODEL_NAME", "all-MiniLM-L6-v2")

# Uploads
UPLOAD_DIR = os.getenv("UPLOAD_DIR", "uploaded_code")

# Java source root (used by code ingestion)
# Can be set dynamically by API (/upload) via env for the ingestion subprocess.
JAVA_ROOT_DIR = os.getenv(
    "JAVA_ROOT_DIR",
    "/Users/pnl11e4o/Documents/Thesis Project/code/scripts/uploaded_code/jhipster-sample-app/src/main/java",
)

# Neo4j
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASS = os.getenv("NEO4J_PASS", "123456789")
