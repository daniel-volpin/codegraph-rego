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

## Rebuilding a managed index

From the repository root, in a provisioned application environment with access to the intended Neo4j graph, source checkout, and embedding model:

```sh
uv run --locked python -m scripts.ingestion.build_code_embeddings --rebuild-index
```

Use the configured credential mechanism; do not place passwords in shell history. This operation reads the graph and source, runs embedding inference, and writes index artifacts. It was not run against the home server during baseline work. The lightweight review environment intentionally lacks the ML dependencies and cannot perform this rebuild. A first model download or a full dependency sync can be substantial; provision them separately under the applicable resource/approval policy rather than treating the command as a lightweight readiness probe.
