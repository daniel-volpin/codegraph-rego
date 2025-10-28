from sentence_transformers import SentenceTransformer
from neo4j import GraphDatabase
import faiss
import numpy as np
import json
import os
from datetime import datetime, timezone
from typing import Callable

from codegraph.config import (
    NEO4J_URI,
    NEO4J_USER,
    NEO4J_PASS,
    EMBEDDING_MODEL_NAME,
    INDEX_DIR,
    EMBEDDING_METADATA_PATH,
)

CONTEXT_LINES_BEFORE = 5
CONTEXT_LINES_AFTER = 20

class EmbeddingService:
    """
    Service for building code embeddings and FAISS index for semantic code search.
    """

    @staticmethod
    def extract_method_snippet(file_path: str, method_name: str) -> str:
        from codegraph.common.snippet_utils import extract_code_snippet
        return extract_code_snippet(file_path, method_name, before=CONTEXT_LINES_BEFORE, after=CONTEXT_LINES_AFTER)

    @staticmethod
    def build_embeddings(progress_callback: Callable[[str, str, float], None] | None = None) -> None:
        """
        Main workflow:
        1. Query Neo4j for all methods, retrieving their signature, name, and file path.
        2. For each method, extract a code snippet from the source file.
        3. Generate embeddings for all extracted code snippets using SentenceTransformer.
        4. Build a FAISS index for fast vector search and save it to disk.
        5. Save the mapping from FAISS index to method signatures as a JSON file.
        """
        method_texts = []
        signatures = []
        if progress_callback:
            progress_callback("embedding", "Fetching methods from Neo4j…", 82.0)
        model = SentenceTransformer(EMBEDDING_MODEL_NAME)
        with GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS)) as driver:
            with driver.session() as session:
                results = session.run(
                    "MATCH (m:Method) RETURN coalesce(m.full_signature, m.signature) AS sig, m.name AS name, m.file_path AS path"
                )
                for record in results:
                    code = EmbeddingService.extract_method_snippet(record["path"], record["name"])
                    if code:
                        method_texts.append(code)
                        signatures.append(record["sig"])
        print(f"Embedding {len(method_texts)} methods...")
        if progress_callback:
            progress_callback("embedding", f"Encoding {len(method_texts)} methods…", 86.0)
        vectors = model.encode(method_texts, normalize_embeddings=True)
        vectors_np = np.asarray(vectors, dtype="float32")
        print(f"vectors_np shape: {vectors_np.shape}, dtype: {vectors_np.dtype}")
        os.makedirs(INDEX_DIR, exist_ok=True)
        index_path = os.path.join(INDEX_DIR, "code_embeddings.index")
        sigmap_legacy_path = os.path.join(INDEX_DIR, "embedding_signature_map.json")
        sigmap_full_path = os.path.join(INDEX_DIR, "embedding_full_signature_map.json")
        if vectors_np.shape[0] > 0:
            dim = int(vectors_np.shape[1])
            index = faiss.IndexFlatIP(dim)
            # Ensure vectors_np is 2D and non-empty before adding
            if vectors_np.ndim == 2 and vectors_np.shape[0] > 0:
                index.add(vectors_np)
                faiss.write_index(index, index_path)
                if progress_callback:
                    progress_callback("embedding", "FAISS index written to disk.", 92.0)
        else:
            # No vectors: do not create or save index
            index = None
            dim = None
        with open(sigmap_full_path, "w") as f:
            json.dump(signatures, f)
        try:
            with open(sigmap_legacy_path, "w") as f:
                json.dump(signatures, f)
        except Exception:
            pass
        if progress_callback:
            progress_callback("embedding", "Embedding metadata saved.", 95.0)
        metadata = {
            "model": EMBEDDING_MODEL_NAME,
            "dim": dim,
            "metric": "cosine",
            "count": len(signatures),
            "built_at": datetime.now(timezone.utc).isoformat(),
            "index_path": index_path,
            "signature_map": {
                "full": sigmap_full_path,
                "legacy": sigmap_legacy_path
            }
        }
        try:
            with open(EMBEDDING_METADATA_PATH, "w") as f:
                json.dump(metadata, f, indent=2)
        except Exception:
            pass
        print(
            f"Done. Saved FAISS index to {index_path} and signature map to {sigmap_full_path}."
        )
        if progress_callback:
            progress_callback("embedding", "Embedding build complete.", 98.0)
