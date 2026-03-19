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

Use these as the thesis benchmark baselines for this repository state:
- detection: `outputs/detection_calibration_path_precision_v4/`
  - precision `0.8357`
  - recall `0.7639`
  - F1 `0.7982`
- explanation: `outputs/thesis_final_explanation_full/`
  - surfaced true positives evaluated: `112`
  - `Citation@Context=0.8125`
  - `Citation@NoContext=0.8125`
- remediation: `outputs/repro_supported_medium_branch_benchmarktest01017_fix/`
  - compile-backed supported remediation: `17/17` fully verified

Keep these separate from:
- `outputs/final_full_remediation_current_main/`, which is a regression/reference run
- `outputs/case_study_spring_petclinic/` and `outputs/case_study_gs_securing_web/`, which are transferability case studies

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

`GET /health` now reports explicit degraded startup state. It returns `200` only when startup preload and the core runtime checks are healthy; otherwise it returns `503` with structured details for the degraded component(s).

## Reproducibility

Use [REPRODUCIBILITY.md](./REPRODUCIBILITY.md) for the shortest path to rerun the benchmark pipeline.

Use [.opencode/project/runbook.md](./.opencode/project/runbook.md) for:
- the current authoritative output directories
- reporting commands
- which runs should be cited versus treated as reference-only

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
