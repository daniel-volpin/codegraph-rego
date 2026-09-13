# Release Policy

CodeGraph follows semantic versioning for repository releases.

## Versioning

- `0.x` releases may change APIs, configuration, benchmark tooling, and artifact
  layouts while the research framework is still evolving.
- Patch releases contain compatible fixes and documentation corrections.
- Minor releases may add capabilities or intentionally revise pre-1.0
  interfaces.
- `1.0.0` is reserved for an intentionally stable public API and documented
  artifact scope.

## Release requirements

A release must:

1. originate from a green `main` commit;
2. align `pyproject.toml`, `uv.lock`, `frontend/package.json`, and
   `CITATION.cff`;
3. preserve canonical evidence and record any new benchmark provenance;
4. pass the repository release checklist;
5. publish GitHub release notes that state research scope and limitations.

Git tags and GitHub releases identify source revisions. CodeGraph is currently distributed from source; no PyPI package or production container image is part of the supported release contract.

Two tag schemes are in use and should stay distinct:

- Release tags are `vX.Y.Z`, matching the `version` in `pyproject.toml`.
- Evidence tags are `<subject>-<version-or-date>-source` and pin the commit an artifact's `provenance.json` records, because this repository squash-merges and a feature-branch commit never becomes an ancestor of `main`. `outputs/README.md` maps each artifact to its tag. `thesis-evidence-2026-05-31-source` is the one exception to the per-run rule: it pins a whole evidence package.

See [`release_checklist.md`](./release_checklist.md) for the operational gate and [`public_release_checklist.md`](./public_release_checklist.md) for the separate private-to-public transition.
