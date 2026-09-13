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

See [`release_checklist.md`](./release_checklist.md) for the operational gate and [`public_release_checklist.md`](./public_release_checklist.md) for the separate private-to-public transition.
