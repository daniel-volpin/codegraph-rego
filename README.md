# CodeGraph

[![CI](https://github.com/daniel-volpin/codegraph-rego/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/daniel-volpin/codegraph-rego/actions/workflows/ci.yml) [![GitHub release](https://img.shields.io/github/v/release/daniel-volpin/codegraph-rego)](https://github.com/daniel-volpin/codegraph-rego/releases/latest) [![Python](https://img.shields.io/badge/python-3.14%2B-blue)](./pyproject.toml) [![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](./LICENSE) [![Citation](https://img.shields.io/badge/citation-CITATION.cff-orange)](./CITATION.cff)

**Benchmark-backed security and compliance analysis for Java applications.**

CodeGraph parses Java with Eclipse JDT, stores graph-structured evidence in Neo4j, evaluates security policies through OPA/Rego and OpenGrep, produces evidence-grounded LLM explanations, and verifies remediation candidates in isolated workspaces.

It is a thesis research artifact evaluated primarily against [OWASP Benchmark](https://owasp.org/www-project-benchmark/). It is not a production security scanner or autonomous production repair system.

## Quick Start

Requirements: macOS or Linux, Python 3.14.7, uv 0.12.13+, Node.js 24+, Yarn 1.22+, JDK 21+, Maven, Docker Compose (or compatible Podman Compose), OPA, and OpenGrep. Exact versions and evaluation prerequisites are maintained in [`REPRODUCIBILITY.md`](./REPRODUCIBILITY.md).

```bash
git clone https://github.com/daniel-volpin/codegraph-rego.git
cd codegraph-rego
make install
cp .env.example .env
```

Set `NEO4J_PASS` and any LLM provider settings in `.env`, then run:

```bash
make dev
```

The frontend is served at <http://127.0.0.1:5173> and the API at <http://127.0.0.1:8000>. A fresh checkout reports a degraded health state until a workspace has been ingested and its retrieval index built.

To run the full stack in containers instead:

```bash
make docker-up
# later
make docker-down
```

Generated retrieval artifacts under `index/` are local build products, not portable recorded state. Rebuild them for the active workspace rather than copying an index from another checkout or machine.

## System

```text
Java source
    -> Eclipse JDT
    -> immutable Neo4j workspace revision
    -> OPA/Rego + OpenGrep policy evaluation
    -> findings with evidence
       -> grounded explanation
       -> bounded or agentic remediation
          -> compile + tests + policy re-verification
```

Key boundaries:

- Eclipse JDT is the sole Java parser; missing or ambiguous source evidence fails closed.
- Detection rules declare their owning engine in `configs/benchmark/policy_registry.json`.
- Injection controls use OpenGrep dataflow taint analysis rather than substring matching.
- Graph revisions are immutable and retrieval artifacts are generation-validated.
- Remediation candidates are isolated from the live workspace until verification succeeds.
- Backend DTOs and `frontend/src/lib/schemas.ts` must stay aligned.

See [`docs/architecture/current-baseline.md`](./docs/architecture/current-baseline.md) for the current architecture contract.

## Development

```bash
uv run ruff check .
uv run python -m pytest -q
PATH="$(pwd)/.venv/bin:$PATH" make policy-check
make opengrep-test
make docs-check
(cd frontend && yarn lint && yarn test && yarn build)
```

Useful targets:

```bash
make help
make java-parser-build
make benchmark-corpus
make neo4j-up
make neo4j-down
```

## Research Evidence

Current benchmark commands, runtime configuration, and reproducibility requirements are in [`REPRODUCIBILITY.md`](./REPRODUCIBILITY.md). Benchmark mappings and remediation tiers are in [`docs/benchmark_context.md`](./docs/benchmark_context.md). Historical thesis results, provenance, and claim limitations are in [`docs/thesis_context.md`](./docs/thesis_context.md). Versioned artifacts are indexed by [`outputs/README.md`](./outputs/README.md).

Do not treat recorded benchmark figures as guaranteed performance on arbitrary applications. Cite the underlying artifact and provenance rather than copying a headline metric without its scope.

## Safety

CodeGraph is designed for single-user, loopback-only research use. The API has no authentication or rate limiting, uploaded projects may be compiled during verification, source context may be sent to the configured LLM provider, and remediation apply mode can modify the active workspace.

Keep the service bound to loopback, treat uploaded code as untrusted, and use an appropriate sandbox when compiling third-party projects. See [`SECURITY.md`](./SECURITY.md).

## Documentation

- [`REPRODUCIBILITY.md`](./REPRODUCIBILITY.md) — setup, configuration, validation, and evaluation commands
- [`docs/architecture/current-baseline.md`](./docs/architecture/current-baseline.md) — current architecture and ownership boundaries
- [`docs/frontend_backend_contract.md`](./docs/frontend_backend_contract.md) — API/frontend contract
- [`docs/benchmark_context.md`](./docs/benchmark_context.md) — benchmark mappings and remediation tiers
- [`docs/thesis_context.md`](./docs/thesis_context.md) — research claims, historical evidence, and limitations
- [`docs/architecture/artifact-policy.md`](./docs/architecture/artifact-policy.md) — generated versus versioned artifacts
- [`CONTRIBUTING.md`](./CONTRIBUTING.md) — contribution workflow

## License and Citation

CodeGraph source and documentation are licensed under the [MIT License](./LICENSE). Third-party benchmark material retains its upstream terms; see [`THIRD_PARTY_NOTICES.md`](./THIRD_PARTY_NOTICES.md). Cite the project using [`CITATION.cff`](./CITATION.cff).
