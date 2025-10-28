from __future__ import annotations


def build_embeddings() -> None:
    """Build FAISS embeddings and signature maps by calling the existing script's main()."""
    import build_code_embeddings as _emb

    _emb.main()

