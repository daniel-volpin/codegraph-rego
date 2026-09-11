# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

MSc Software Engineering thesis project (UvA, Daniel Volpin). CodeGraph is a benchmark-backed JVM security/compliance framework that:

1. Ingests JVM code into Neo4j for graph-based code understanding.
2. Evaluates ISO 27001 controls via OPA/Rego policy rules.
3. Generates grounded LLM explanations with structured evidence citations.
4. Performs bounded, confidence-gated remediation with build re-verification.

Primary proof surface: **OWASP Benchmark v1.2**.
Real-world apps are secondary workflow case studies, not the primary evidence surface.

## Commands

### Backend (Python 3.11+, managed with uv)

```bash
make install                        # uv sync + frontend yarn install
uv run python -m pytest -q          # all backend tests (or .venv/bin/python -m pytest)
uv run python -m pytest tests/codegraph/remediation/ -q      # one test directory
uv run python -m pytest tests/codegraph/test_config.py -q    # one test file
uv run python -m pytest -k "test_name" -q                    # one test by name
uv run ruff check .                 # lint (line-length 120, import sorting + pyupgrade enforced)
uv run ruff format .                # format
```

Use `.venv/bin/python -m pytest` or `uv run`, not system `python3`. In sandboxed environments set `UV_CACHE_DIR=/tmp/uv-cache`.

### Policy (OPA v1.15.1 pinned — tests assert the version)

```bash
make policy-check   # opa check --strict + opa fmt --list --fail (check-only, fails on format drift)
make policy-fmt     # rewrite Rego formatting in place
```

### Frontend (Vite + React + TypeScript, from `frontend/`)

```bash
yarn lint            # eslint, --max-warnings 0
yarn test            # vitest run (yarn test:watch for watch mode)
yarn build           # tsc -p tsconfig.app.json && vite build
yarn test:e2e        # playwright (yarn test:e2e:thesis for @thesis-tagged subset)
```

### Run the app

```bash
make dev            # Neo4j via compose + backend + frontend (port 5173)
make backend-dev    # Neo4j via compose + backend only (uvicorn app:app, port 8000)
make neo4j-up       # Neo4j dependency only
```

Requires `.env` (copy `.env.example`) with at least `NEO4J_PASS`. Config is loaded via `codegraph.config.settings` (pydantic-settings); never read env vars ad hoc. Full variable reference lives in `REPRODUCIBILITY.md`.

### Benchmark evaluation runners (root-level, stable entrypoints)

```bash
uv run python run_benchmark_eval.py   --config configs/benchmark/smoke_mixed.json               --mapping configs/benchmark/policy_registry.json --output-dir outputs/<dir> --reset-neo4j
uv run python run_explanation_eval.py --config configs/benchmark/multicat_full.json             --mapping configs/benchmark/policy_registry.json --output-dir outputs/<dir> --reset-neo4j
uv run python run_remediation_eval.py --config configs/benchmark/remediation_bounded_smoke.json --mapping configs/benchmark/policy_registry.json --output-dir outputs/<dir> --sample-size 3 --reset-neo4j
```

Runners need `OWASP_BENCHMARK_ROOT` (local BenchmarkJava checkout) and, for explanation/remediation, an OpenAI-compatible LLM endpoint. Every run writes a `provenance.json` (git SHA, OPA version, model, seed, config hash). The explanation eval supports `--resume`. Exact rerun flow: `REPRODUCIBILITY.md`.

CI (`.github/workflows/ci.yml`) is path-filtered: backend job runs `make policy-check`, `ruff check .`, `pytest -q`; frontend job runs `yarn lint && yarn test && yarn build`.

## Architecture

End-to-end pipeline:

```text
Java source -> ingestion into Neo4j -> policy input bundling -> OPA/Rego evaluation
            -> structured LLM explanation -> bounded remediation -> build re-verification
```

Two strict backend boundaries (see `docs/architecture/repo-layout.md`):

- `api/` — FastAPI HTTP surface only: routers (`upload`, `search`, `policy`, `remediation`, `health`) plus request/response DTOs. Keep routers thin.
- `codegraph/` — all domain logic. `app.py` at the root is just the `uvicorn app:app` entrypoint; `codegraph/app.py` wires routers, request-ID middleware, and startup readiness checks (ingestion, signature map, FAISS index, embedding model).

Key subsystems inside `codegraph/`:

- `config.py` — central pydantic-settings `Settings`; the only sanctioned way to read configuration.
- `ingestion/` — parses Java (javalang) into the Neo4j graph.
- `search/` + `embedding/` — hybrid lexical/vector search over the graph (sentence-transformers + FAISS).
- `policy/` — `runtime/opa.py` builds the **authoritative violation response shape**; `runtime/bundles.py` builds the evidence bundle fed to OPA; `runtime/catalog.py` loads `policy/catalog.json`; `analysis/` holds the per-family source heuristics (injection, crypto, command). Rego rules live in top-level `policy/*.rego` and **must stay aligned with `policy/catalog.json`**.
- `llm/` — OpenAI-compatible client/transport, JSON-schema structured output, and per-task prompting. Explanation returns concise `Citation / Why / Fix`; remediation uses a strict contract of `decision` / `replacement_method_lines` / `reason` (malformed payloads surface as `GENERATION_ERROR`, never parser hacks). Explanation and remediation may use different models.
- `remediation/` — `apply_flow.py` orchestrates preview/apply/verify; `confidence.py` owns the closed-form sigmoid confidence gate (apply / review / abstain bands, thresholds from settings); `verification.py` re-builds the project (Maven) after edits. `NO_FIX` is a valid, expected outcome for guarded categories.
- `evaluation/` — benchmark pipeline behind the root `run_*_eval.py` runners; `remediation_runtime.py` writes remediation calibration artifacts; artifacts land under `outputs/`.

Frontend/backend contract: `frontend/src/lib/schemas.ts` (Zod) is the source of truth; `frontend/src/lib/types.ts` only re-exports derived types. When an API payload changes, update the Zod schemas — never hand-maintain types. See `docs/frontend_backend_contract.md`.

Trust boundary: the service is a single-user, loopback-only research artifact — no auth, no rate limiting, build verification executes uploaded code, and remediation `mode="apply"` mutates the live workspace.

## Benchmark Scope

Eight benchmark-backed categories: CWE-22/78/89/90/643 (path traversal, command, SQL, LDAP, XPath injection → `ISO-A.8-*`) and CWE-327/328/330 (weak crypto/hash/random → `ISO-A.10-*`).

Remediation support tiers: `full` (weak hash, weak random), `guarded` (weak crypto), `manual` (injection families and access/logging rules).

## Working Rules

- Treat `main` as the baseline branch for new promoted benchmark outputs.
- Prefer canonical benchmark configs under `configs/benchmark/`; do not silently change benchmark semantics or control mappings.
- Keep benchmark evidence and qualitative case-study evidence separate.
- Cite `outputs/` artifacts (directory + `provenance.json` SHA), not prose summaries.
- Avoid new top-level scripts; operator utilities belong under `scripts/` (`ingestion/`, `search/`, `policy/`, `evaluation/`).
- Use `logging`, not `print`.

## Thesis Language Constraints

- Say **"graph-based code understanding"** or **"graph-structured evidence"**.
- Do not describe the implementation as a code property graph, control-flow graph, or full taint analysis.
- Describe remediation as bounded and `dry_run` verified, not autonomous production repair.
- Treat `Citation@NoContext=0.000` or `Citation@FP (no-ctx)=0.000` as expected ablation floors, not failures.

## Stable Architecture Anchors

- `codegraph/policy/runtime/opa.py` builds the authoritative violation response shape.
- `codegraph/policy/runtime/bundles.py` builds the evidence bundle.
- `codegraph/remediation/apply_flow.py` handles remediation apply/verify flow.
- `codegraph/remediation/confidence.py` owns remediation confidence scoring.
- `codegraph/evaluation/remediation_runtime.py` writes remediation calibration artifacts.
- `policy/catalog.json` and `configs/benchmark/` must stay aligned with benchmark semantics.

## Important Docs

- `REPRODUCIBILITY.md` — commands, environment setup, env var reference, and rerun flow.
- `copilot-context/benchmark.md` — benchmark scope, evidence anchors, and claim guardrails.
- `docs/thesis_context.md` — thesis framing and terminology constraints.
- `docs/architecture/repo-layout.md` — the `api/` vs `codegraph/` boundary rationale.
- `docs/frontend_backend_contract.md` — API payload contract with the SPA.
