# Contributing

CodeGraph is a Java security and compliance research project. Contributions should preserve reproducibility, evidence provenance, and the repository's fail-closed analysis/remediation contracts.

Read [`AGENTS.md`](./AGENTS.md) before making substantive changes. It is the canonical engineering guide for architecture invariants, policy ownership, remediation safety, and validation expectations.

## Setup

```bash
git clone https://github.com/daniel-volpin/codegraph-rego.git
cd codegraph-rego
make install
cp .env.example .env
```

See [`REPRODUCIBILITY.md`](./REPRODUCIBILITY.md) for runtime requirements and evaluation setup.

## Pull Requests

- Use a focused feature branch; do not make substantial changes directly on `main`.
- Keep the change scoped to one goal and preserve unrelated work.
- Add or update tests for changed behavior.
- Keep backend DTOs and `frontend/src/lib/schemas.ts` aligned.
- Do not silently change benchmark mappings, engine ownership, remediation tiers, or canonical evidence.
- Do not overwrite versioned research artifacts for an incidental rerun.
- Use clear commit messages such as `feat:`, `fix:`, `docs:`, `test:`, or `chore:`.

## Validation

Run the gates relevant to the change:

```bash
uv run ruff check .
uv run python -m pytest -q
PATH="$(pwd)/.venv/bin:$PATH" make policy-check
make opengrep-test
make docs-check
(cd frontend && yarn lint && yarn test && yarn build)
```

Java-adapter changes also require `make java-parser-build`. Benchmark-sensitive changes require the focused evaluation commands in [`REPRODUCIBILITY.md`](./REPRODUCIBILITY.md).

If a required external prerequisite is unavailable, state that clearly in the pull request instead of substituting a weaker check and calling it equivalent.

All contributors are expected to follow [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md). Security issues should be reported privately as described in [`SECURITY.md`](./SECURITY.md).
