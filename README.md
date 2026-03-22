# CodeGraph

CodeGraph is a benchmark-backed JVM security and compliance framework. Its primary proof surface is **OWASP Benchmark**. Real-world applications are used as secondary workflow case studies, not as the main scientific evidence.

## What It Does

CodeGraph ingests Java code into Neo4j, evaluates OPA/Rego policies, produces structured explanations, and performs bounded remediation with re-verification.

Core flow:

- ingest Java into a graph
- evaluate ISO-aligned security rules
- explain surfaced findings with structured `citation / why / fix`
- attempt bounded remediation where supported
- re-verify the result

## Benchmark Scope

Current benchmark-backed categories:

- `CWE-22` → `ISO-A.8-PATH-TRAVERSAL`
- `CWE-78` → `ISO-A.8-CMD-INJECTION`
- `CWE-89` → `ISO-A.8-SQL-INJECTION`
- `CWE-90` → `ISO-A.8-LDAP-INJECTION`
- `CWE-327` → `ISO-A.10-WEAK-CRYPTO`
- `CWE-328` → `ISO-A.10-WEAK-HASH`
- `CWE-330` → `ISO-A.10-WEAK-RANDOM`
- `CWE-643` → `ISO-A.8-XPATH-INJECTION`

Remediation support tiers:

- `full`: weak hash, weak random
- `guarded`: weak crypto
- `manual`: injection families and access/logging rules

## Authoritative Baselines

Thesis-final benchmark outputs produced on `main` on 2026-03-22:

- detection: `outputs/thesis_final_detection_full/`
  - precision `0.953`, recall `0.953`, F1 `0.953`
  - 8 CWE categories · 454 OWASP Benchmark cases (seed=7, 60/category)
- explanation: `outputs/thesis_final_explanation_full/`
  - 222 true positives evaluated across all 8 categories
  - `Citation@Context=0.9955` · `Citation@NoContext=0.000`
- remediation: `outputs/thesis_final_remediation_v2/`
  - 25/25 fully verified (`dry_run`, fix and build success rate 1.000)
  - confidence calibration populated: Brier=0.006, ECE=0.070

Historical runs (preserved for provenance, not for citation):

- `outputs/detection_calibration_path_precision_v4/` — pre-taint intermediate baseline (F1=0.798)
- `outputs/repro_supported_medium_branch_benchmarktest01017_fix/` — pre-confidence-gate remediation reference (17/17, pre-PR #81)
- `outputs/final_full_remediation_current_main/` — 10-case regression/reference run

Keep case studies separate from benchmark evidence:

- `outputs/case_study_spring_petclinic/` and `outputs/case_study_gs_securing_web/` — transferability case studies

## Quick Start

Prerequisites:

- Python 3.10+
- Neo4j 5.x
- OPA on `PATH`
- Java + Maven for benchmark/remediation verification

Install:

```bash
make install
```

Run the app:

```bash
make dev
```

`make dev` now starts the local Neo4j dependency with Docker Compose, waits for it to become healthy, and then launches the backend and frontend. You no longer need Neo4j Desktop running for the normal local development flow.

If Docker is unavailable and Podman is installed, the Make targets automatically fall back to `podman compose`. You can still override the compose command explicitly if you want:

```bash
make dev DOCKER_COMPOSE="podman compose"
```

If you only want the backend:

```bash
make backend-dev
```

## Verification

Use the backend test invocation below as the canonical local command on this branch:

```bash
UV_CACHE_DIR=/tmp/uv-cache uv run python -m pytest -q
```

Runtime-hygiene gate:

```bash
.venv/bin/ruff check .
UV_CACHE_DIR=/tmp/uv-cache uv run python -m pytest -q tests/test_app_startup.py tests/test_health_router.py tests/test_policy_router.py tests/test_upload_router.py tests/test_remediation_router.py tests/test_start_backend_dev.py
cd frontend && yarn build
```

Branch smoke contract:

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

Key endpoints:

- `POST /upload`
- `POST /search`
- `GET /policy/evaluate`
- `POST /policy/evaluate_with_llm`
- `POST /policy/explain_one`
- `POST /remediation/preview`
- `POST /remediation/apply`
- `GET /health`

## Configuration

Runtime configuration is loaded via `codegraph.config.get_settings()` (lazy, cached).

Key environment variables:

- `NEO4J_URI`
- `NEO4J_USER`
- `NEO4J_PASS` (required at runtime)
- `LLM_PROVIDER`
- `LLM_MODEL`
- `LLM_API_BASE`
- `LLM_API_KEY`
- `LLM_TEMPERATURE` (must be in `[0, 2]`)
- `LLM_CONCURRENCY` (must be `>= 1`)
- `REMEDIATION_CONFIDENCE_THRESHOLD_APPLY` (must be in `[0, 1]`)
- `REMEDIATION_CONFIDENCE_THRESHOLD_REVIEW` (must be in `[0, 1]`)
- `REMEDIATION_CONFIDENCE_TEMPERATURE` (must be `> 0`)

Use `.env.example` as the canonical local template. Startup performs runtime validation and reports degraded startup status if required runtime settings are missing.

`GET /health` now reports explicit degraded startup state. It returns `200` only when startup preload and the core runtime checks are healthy; otherwise it returns `503` with structured details for the degraded component(s).

## Reproducibility

Use [REPRODUCIBILITY.md](./REPRODUCIBILITY.md) for the shortest path to rerun the benchmark pipeline.

Use [docs/release_checklist.md](./docs/release_checklist.md) for the minimal release flow so Git tags, release notes, and manifest versions stay aligned.

Use [.opencode/project/runbook.md](./.opencode/project/runbook.md) for:

- the current authoritative output directories
- reporting commands
- which runs should be cited versus treated as reference-only

## Release

Current lightweight release process:

- update [pyproject.toml](./pyproject.toml) and [frontend/package.json](./frontend/package.json) to the intended release version
- verify `main` is clean and CI is green
- create the GitHub tag and release from `main`
- keep the release title, notes, and manifest versions synchronized

Use [docs/release_checklist.md](./docs/release_checklist.md) for the step-by-step checklist.

## Repo Layout

- [app.py](./app.py): FastAPI entrypoint
- [api](./api): HTTP routers and request/response models
- [codegraph](./codegraph): backend domain logic
- [configs/benchmark](./configs/benchmark): canonical benchmark configs
- [policy](./policy): OPA/Rego rules and catalog
- [scripts](./scripts): evaluation and operator utilities
- [docs/architecture](./docs/architecture): architecture notes

## Notes

- Use `codegraph.config.settings`; do not read env vars ad hoc in new backend code.
- Keep browser access aligned with `codegraph.config.settings.cors_allowed_origins`; avoid wildcard credentialed CORS.
- Keep `policy/catalog.json` aligned with Rego rules.
- Benchmark claims should cite `outputs/`, not README prose.
- Real-world case studies should not be presented as the primary evidence surface.

## Citation & License

- Cite the repository using [CITATION.cff](./CITATION.cff).
- This repository is licensed under the [MIT License](./LICENSE).
