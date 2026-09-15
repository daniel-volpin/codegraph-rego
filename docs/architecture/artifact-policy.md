# Artifact Policy

CodeGraph distinguishes maintained source, versioned research evidence, and generated local state.

## Maintained Source

Keep hand-maintained code, policies, configuration, tests, and documentation in Git.

## Versioned Research Evidence

Only evidence intentionally needed to support recorded research claims belongs in Git. This currently includes selected `outputs/thesis_final_*` artifacts, `outputs/canonical_manifest.sha256`, and the summary/provenance files retained for the current full-corpus detection baseline.

Canonical thesis evidence is protected by `tests/test_canonical_artifacts.py`. An intentional evidence regeneration must update the artifact and canonical manifest together.

See [`../../outputs/README.md`](../../outputs/README.md) for the evidence index.

## Generated Local State

Do not commit ordinary runtime/build output, including:

- retrieval artifacts under `index/`;
- upload workspaces under `uploaded_code/`;
- non-canonical evaluation runs under `outputs/`;
- temporary policy bundles, logs, caches, and tool scratch state.

Retrieval artifacts are workspace-generation specific and must be rebuilt for the active workspace. Prefer documenting a deterministic regeneration command over committing generated state.

A new generated artifact should be versioned only when it is deliberately part of the research evidence surface and has enough provenance to support the claim for which it is retained.
