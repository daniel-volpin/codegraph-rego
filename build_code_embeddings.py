"""
build_code_embeddings.py

Extracts code snippets for each method (from file paths stored in Neo4j), generates embeddings using SentenceTransformer,
and builds a FAISS index for semantic code search using cosine similarity (IP over normalized vectors).
The signature map uses the overload-safe `full_signature` value (falls back to `signature` if missing).
"""

from sentence_transformers import SentenceTransformer
from neo4j import GraphDatabase
import faiss
import numpy as np
import json
import os
from datetime import datetime, timezone
from config import (
    NEO4J_URI,
    NEO4J_USER,
    NEO4J_PASS,
    EMBEDDING_MODEL_NAME,
    INDEX_DIR,
    EMBEDDING_METADATA_PATH,
)

# Number of lines to include before and after the method name for context in the extracted code snippet
CONTEXT_LINES_BEFORE = 5
CONTEXT_LINES_AFTER = 20


def extract_method_snippet(file_path: str, method_name: str) -> str:
    """
    Extract a code snippet for a method from a Java file.
    This is a heuristic: it grabs lines around the first occurrence of the method name.
    Returns the snippet as a string, or None if not found.
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        # Find all lines containing the method name
        match_lines = [i for i, line in enumerate(lines) if method_name in line]
        if not match_lines:
            return ""
        idx = match_lines[0]
        start = max(0, idx - CONTEXT_LINES_BEFORE)
        end = min(len(lines), idx + CONTEXT_LINES_AFTER)
        return ''.join(lines[start:end])
    except Exception as e:
        print(f"[ERROR] Failed to extract from {file_path}: {e}")
        return ""


def main():
    """
    Main workflow:
    1. Query Neo4j for all methods, retrieving their signature, name, and file path.
    2. For each method, extract a code snippet from the source file.
    3. Generate embeddings for all extracted code snippets using SentenceTransformer.
    4. Build a FAISS index for fast vector search and save it to disk.
    5. Save the mapping from FAISS index to method signatures as a JSON file.
    """
    method_texts = []  # List of code snippets for embedding
    signatures = []    # Corresponding method signatures

    model = SentenceTransformer(EMBEDDING_MODEL_NAME)

    # Query Neo4j for all methods
    with GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS)) as driver:
        with driver.session() as session:
            results = session.run(
                "MATCH (m:Method) RETURN coalesce(m.full_signature, m.signature) AS sig, m.name AS name, m.file_path AS path"
            )
            for record in results:
                # Extract a code snippet for each method
                code = extract_method_snippet(record["path"], record["name"])
                if code:
                    method_texts.append(code)
                    signatures.append(record["sig"])

    print(f"Embedding {len(method_texts)} methods...")

    # Generate embeddings for all code snippets
    vectors = model.encode(method_texts, normalize_embeddings=True)

    # Save index and signature map in a dedicated folder
    os.makedirs(INDEX_DIR, exist_ok=True)
    index_path = os.path.join(INDEX_DIR, "code_embeddings.index")
    sigmap_legacy_path = os.path.join(INDEX_DIR, "embedding_signature_map.json")
    sigmap_full_path = os.path.join(INDEX_DIR, "embedding_full_signature_map.json")

    # Build and save the FAISS index using IP on normalized vectors (cosine similarity)
    index = faiss.IndexFlatIP(vectors.shape[1])
    index.add(np.asarray(vectors, dtype="float32"))

    # Save the mapping from FAISS index to method full-signatures (and legacy path for compatibility)
    with open(sigmap_full_path, "w") as f:
        json.dump(signatures, f)
    try:
        with open(sigmap_legacy_path, "w") as f:
            json.dump(signatures, f)
    except Exception:
        pass
    faiss.write_index(index, index_path)
    # Write metadata for validation/debug
    metadata = {
        "model": EMBEDDING_MODEL_NAME,
        "dim": int(vectors.shape[1]),
        "metric": "cosine",
        "count": len(signatures),
        "built_at": datetime.now(timezone.utc).isoformat(),
        "index_path": index_path,
        "signature_map": {
            "full": sigmap_full_path,
            "legacy": sigmap_legacy_path,
        },
    }
    try:
        with open(EMBEDDING_METADATA_PATH, "w") as f:
            json.dump(metadata, f, indent=2)
    except Exception:
        pass
    print(
        f"Done. Saved FAISS index to {index_path} and signature map to {sigmap_full_path}."
    )


if __name__ == "__main__":
    main()
