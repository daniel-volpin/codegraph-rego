# Retrieval generation migration notes (2026-09-11)

- Managed retrieval paths now require `embedding_generation_manifest.v1`.
  - Older `embedding_metadata.json` formats are explicitly rejected.
  - Migration path: rebuild embeddings to publish a managed generation manifest.
- Managed readers are strict:
  - Index/map/metadata hashes are revalidated on each managed load.
  - Model, dimension, and count mismatches fail closed.
- Explicit externally supplied paths remain compatibility mode (unverified by managed manifest semantics).
- Publication now switches a single manifest atomically to immutable generation files.
- Prior generation files are retained; no automatic garbage collection is performed.
- This mechanism is **artifact-generation isolation**, not source snapshot isolation.
- Per-load hash validation adds I/O; benchmark impact has not yet been measured.
