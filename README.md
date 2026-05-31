# CodeGraph

[![CI](https://github.com/daniel-volpin/codegraph-rego/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/daniel-volpin/codegraph-rego/actions/workflows/ci.yml)
[![Version](https://img.shields.io/github/v/tag/daniel-volpin/codegraph-rego?label=version)](https://github.com/daniel-volpin/codegraph-rego/tags)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](./pyproject.toml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](./LICENSE)
[![Citation](https://img.shields.io/badge/citation-CITATION.cff-orange)](./CITATION.cff)

CodeGraph is a benchmark-backed JVM security and compliance framework for ingesting Java code into a graph, evaluating ISO-aligned OPA/Rego policies, generating grounded explanations, and attempting bounded remediation with re-verification.

## Highlights

- Primary proof surface is **OWASP Benchmark**, not ad hoc case studies.
- End-to-end flow: ingestion -> policy evaluation -> explanation -> remediation -> re-verification.
- Covers 8 benchmark-backed CWE/ISO categories today.
- Supports structured explanation output with concise `Citation / Why / Fix`.
- Supports bounded remediation tiers for selected categories.
- Ships with reproducible outputs under [`outputs/`](./outputs/) and a rerun guide in [`REPRODUCIBILITY.md`](./REPRODUCIBILITY.md).

## Research Scope

CodeGraph is a **research artifact first**.

- Primary evidence comes from benchmark-backed evaluation.
- Real-world apps are treated as secondary workflow case studies.
- The service is designed for **single-user, loopback-only** operation unless separately hardened.

If you are evaluating thesis claims, start with:

- [`REPRODUCIBILITY.md`](./REPRODUCIBILITY.md)
- [`outputs/`](./outputs/)
- [`docs/thesis_context.md`](./docs/thesis_context.md)

## Quick Start

### Prerequisites

- Python 3.10+
- Node.js + Yarn
- Neo4j 5.x
- OPA on `PATH`
- Java + Maven for benchmark and remediation verification

### Install

```bash
make install
cp .env.example .env
```

Fill in at least `NEO4J_PASS` in `.env`. The local dev scripts export `CODEGRAPH_ENV_FILE=$PWD/.env` automatically.

### Run

Backend + frontend:

```bash
make dev
```

Backend only:

```bash
make backend-dev
```

`make dev` and `make backend-dev` start the local Neo4j dependency with Compose, wait for it to become healthy, and then launch the app. If Docker is unavailable and Podman is installed, the wrapper scripts can fall back to `podman compose`.

## How It Works

```text
Java source
  -> ingestion into Neo4j
  -> policy input bundling
  -> OPA/Rego evaluation
  -> structured explanation
  -> bounded remediation
  -> verification + benchmark artifacts
```

Core flow:

- ingest Java into a graph
- evaluate ISO-aligned security rules
- explain findings with structured `citation / why / fix`
- attempt bounded remediation where supported
- re-verify the result

For deeper architecture notes, see:

- [`docs/architecture/artifact-policy.md`](./docs/architecture/artifact-policy.md)
- [`docs/architecture/repo-layout.md`](./docs/architecture/repo-layout.md)
- [`docs/frontend_backend_contract.md`](./docs/frontend_backend_contract.md)

## Benchmark Scope

Current benchmark-backed categories:

- `CWE-22` -> `ISO-A.8-PATH-TRAVERSAL`
- `CWE-78` -> `ISO-A.8-CMD-INJECTION`
- `CWE-89` -> `ISO-A.8-SQL-INJECTION`
- `CWE-90` -> `ISO-A.8-LDAP-INJECTION`
- `CWE-327` -> `ISO-A.10-WEAK-CRYPTO`
- `CWE-328` -> `ISO-A.10-WEAK-HASH`
- `CWE-330` -> `ISO-A.10-WEAK-RANDOM`
- `CWE-643` -> `ISO-A.8-XPATH-INJECTION`

Remediation support tiers:

- `full`: weak hash, weak random
- `guarded`: weak crypto
- `manual`: injection families and access/logging rules

Canonical benchmark configs live under [`configs/benchmark/`](./configs/benchmark/).

## Results

Authoritative thesis-final artifact families:

| Surface | Artifact directory | Headline |
| --- | --- | --- |
| Detection | [`outputs/thesis_final_detection_full_v2/`](./outputs/thesis_final_detection_full_v2/) | precision `0.953`, recall `0.953`, F1 `0.953` with provenance + CIs |
| Explanation | [`outputs/thesis_final_explanation_full_v2/`](./outputs/thesis_final_explanation_full_v2/) | `Citation@TP=1.000`, `Citation@FP=1.000`, with provenance |
| Remediation | [`outputs/thesis_final_remediation_v2/`](./outputs/thesis_final_remediation_v2/) | `25/25` fully verified in the thesis-final v2 run |

Follow-up artifact families:

- remediation v3: [`outputs/thesis_final_remediation_v3/`](./outputs/thesis_final_remediation_v3/) when present
- stronger provenance-backed remediation anchor: [`outputs/pr_full_verification_2026-05-11/`](./outputs/pr_full_verification_2026-05-11/) when needed for threshold-based thesis framing

Use artifact directories, tags, and recorded commit provenance when citing results. Do **not** cite README prose as the primary evidence source.

## Verification

Canonical local verification:

```bash
uv run ruff check .
uv run pytest -q
cd frontend && yarn build
```

Benchmark-sensitive smoke runs:

```bash
python run_benchmark_eval.py \
  --config configs/benchmark/smoke_mixed.json \
  --mapping configs/benchmark/policy_registry.json \
  --output-dir outputs/branch_baseline_recovery/detection_smoke \
  --reset-neo4j

python run_remediation_eval.py \
  --config configs/benchmark/remediation_bounded_smoke.json \
  --mapping configs/benchmark/policy_registry.json \
  --output-dir outputs/branch_baseline_recovery/remediation_bounded_smoke \
  --sample-size 3 \
  --reset-neo4j
```

For the shortest rerun path, use [`REPRODUCIBILITY.md`](./REPRODUCIBILITY.md).

## HTTP API

Key endpoints:

- `POST /upload`
- `GET /upload/status?request_id=<id>`
- `GET /upload/status/stream?request_id=<id>` (Server-Sent Events)
- `POST /search`
- `GET /policy/evaluate`
- `POST /policy/evaluate_with_llm`
- `POST /policy/explain_one`
- `POST /remediation/preview`
- `POST /remediation/apply`
- `GET /healthz`
- `GET /readyz`
- `GET /health`

Operational notes:

- Every response carries an `X-Request-Id` header.
- `POST /upload` returns a per-upload `request_id` in the JSON body for progress polling.
- Unhandled exceptions return `{"error": "internal", "request_id": "..."}`.
- `GET /healthz` is a cheap liveness probe with no external I/O.
- `GET /readyz` is a deeper readiness probe and returns `503` with structured details when degraded.

## Configuration

Runtime settings are loaded via `codegraph.config.get_settings()` and validated centrally.

Important environment variables:

- `NEO4J_URI`
- `NEO4J_USER`
- `NEO4J_PASS`
- `LLM_PROVIDER`
- `LLM_MODEL`
- `LLM_API_BASE`
- `LLM_API_KEY`
- `LLM_TEMPERATURE`
- `LLM_CONCURRENCY`
- `REMEDIATION_CONFIDENCE_THRESHOLD_APPLY`
- `REMEDIATION_CONFIDENCE_THRESHOLD_REVIEW`
- `REMEDIATION_CONFIDENCE_TEMPERATURE`

Use [`.env.example`](./.env.example) as the local template.

## Repository Guide

- [`app.py`](./app.py): FastAPI entrypoint for `uvicorn app:app`
- [`api/`](./api): HTTP routers and request/response models
- [`codegraph/`](./codegraph): backend domain logic
- [`configs/benchmark/`](./configs/benchmark/): canonical benchmark configs
- [`policy/`](./policy): OPA/Rego rules and catalog
- [`scripts/`](./scripts): operator and evaluation utilities
- [`docs/`](./docs): architecture, contract, and thesis context notes

## Safety / Trust Boundary

CodeGraph is designed and tested as a **single-user, loopback-only research service**.

Assumptions baked into the codebase:

- The HTTP API has no authentication and no rate limiting.
- The upload workspace is a single shared directory.
- Build verification can execute code from uploaded JVM projects.
- Remediation `mode="apply"` mutates the live workspace.

Safe-operation guidance:

- Bind the API to `127.0.0.1` only unless you add a hardened front door.
- Treat uploaded archives as untrusted code.
- Sandbox build verification if you accept arbitrary uploads.
- Do not treat the current container setup as a production sandbox.

For broader hardening, treat that as a separate engineering effort beyond the thesis artifact.

## Reproducibility & Release

- Rerun guidance: [`REPRODUCIBILITY.md`](./REPRODUCIBILITY.md)
- Release checklist: [`docs/release_checklist.md`](./docs/release_checklist.md)
- Benchmark evidence context: [`copilot-context/benchmark.md`](./copilot-context/benchmark.md)

## Contributing

Pull requests are welcome, but benchmark semantics and control mappings should not be changed casually.

Before proposing backend changes:

- keep `api/` thin and business logic in `codegraph/`
- use `codegraph.config.settings`, not ad hoc env reads
- keep `policy/catalog.json` aligned with Rego rules
- update tests and artifact-facing claims when behavior changes

If a change affects benchmark-sensitive logic, include the relevant smoke run or output artifact reference.

## Citation & License

- Cite the repository using [`CITATION.cff`](./CITATION.cff).
- This repository is licensed under the [MIT License](./LICENSE).
