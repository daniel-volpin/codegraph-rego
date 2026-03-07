# Artifact Policy

This repository contains three artifact classes:

## Source-controlled source files

These are hand-maintained and should remain in git:

- Python backend code
- frontend code
- Rego policies and configs
- tests and documentation

## Generated but intentionally versioned reproducibility artifacts

These remain tracked because they support thesis reproducibility and validated local runs:

- `index/code_embeddings.index`
- `index/embedding_metadata.json`
- `index/embedding_signature_map.json`
- `index/embedding_full_signature_map.json`

Treat these as reproducibility assets, not as primary source files.

## Generated local/runtime artifacts

These should not be committed:

- temporary OPA bundles such as `tmp_bundle.json`
- evaluation outputs under `outputs/`
- upload workspaces under `uploaded_code/`
- log files
- caches such as `__pycache__/`, `.pytest_cache/`, and similar local tool state

When a generated artifact is needed for reproducibility, prefer documenting its regeneration flow and tracking it only if it is intentionally part of the thesis evidence surface.
