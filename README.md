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

Thesis-final benchmark outputs produced on `main` on 2026-03-22 (tagged
`thesis-final-v1`):

- detection: `outputs/thesis_final_detection_full/`
  - precision `0.953`, recall `0.953`, F1 `0.953`
  - 8 CWE categories · 454 OWASP Benchmark cases (seed=7, 60/category)
- explanation: `outputs/thesis_final_explanation_full/`
  - 222 true positives evaluated across all 8 categories
  - `Citation@Context=0.9955` · `Citation@NoContext=0.000`
  - These v1 numbers measure grounding on the **TP cohort only**; the v2
    artifact set (see below) extends this with a parallel FP cohort.
- remediation: `outputs/thesis_final_remediation_v2/`
  - 25/25 fully verified (`dry_run`, fix and build success rate 1.000)
  - confidence calibration: Brier=0.006, ECE=0.070, computed over the
    **full** population (every result with a confidence score, including
    `NO_FIX` abstentions). The v3 artifact set adds a per-population
    breakdown that isolates attempted-only and no_fix-only Brier/ECE.

### Defensibility Pass (PR `thesis/defensibility-pass`, in progress)

The defensibility pass introduces three additive metric surfaces. The
legacy headline numbers above remain valid; the new surfaces appear
alongside them in a fresh `_v2`/`_v3` artifact namespace so that v1 stays
recoverable as the thesis-locked baseline.

- detection v2 — `outputs/thesis_final_detection_full_v2/`
  - same point estimates (P/R/F1) plus bootstrap 95% CIs
    (`precision_ci`, `recall_ci`, `f1_ci`) and Wilson 95% intervals as a
    closed-form sanity check (`precision_ci_wilson`, `recall_ci_wilson`).
  - new `provenance.json` capturing git SHA, OPA version, model id,
    seed, and config hash.
- explanation v2 — `outputs/thesis_final_explanation_full_v2/`
  - **TP cohort** (legacy semantics): `Citation@TP = with-context citation
    rate over violations on positive testcases`. Reported as the legacy
    top-level fields plus an explicit `tp.*` block, with Wilson 95% CIs.
  - **FP cohort** (new): `Citation@FP = with-context citation rate over
    violations on benign testcases` — i.e. grounding on the detector's
    false positives. Reported in a `fp.*` block.
  - `Citation@NoContext` reported per cohort.
- remediation v3 — `outputs/thesis_final_remediation_v3/`
  - Calibration computed over **three populations** simultaneously:
    `full` (legacy headline; matches the v2 artifact above), `attempted_only`
    (status in `OK / GENERATION_ERROR / REPLACEMENT_ERROR / BUILD_ERROR /
    VERIFICATION_ERROR` — i.e. the system actually tried to fix something),
    and `no_fix_only` (declared abstentions). The attempted-only Brier/ECE
    measures calibrated success probability; the no_fix-only block measures
    knew-when-to-abstain behavior. Legacy top-level Brier/ECE remains an
    alias of the full population so existing artifact consumers keep working.

When citing thesis-final numbers in prose, cite the artifact directory
plus the git tag (`thesis-final-v1`). When citing the v2/v3 numbers, cite
the artifact directory plus the commit SHA recorded in its
`provenance.json`.

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

## Deployment Model & Trust Boundary

CodeGraph is designed and tested as a **single-user, loopback-only research
service**. The deployment model is intentionally narrow; reading this section
before exposing the service is mandatory.

**Assumptions baked into the codebase.**

- The HTTP API has **no authentication and no rate limiting**. Every endpoint
  (upload, policy evaluation, remediation preview/apply) is fully open. CORS
  defaults whitelist `localhost:5173/4173/8000` only.
- The upload workspace is a **single shared directory** on the server
  (`UPLOAD_DIR`, default `uploaded_code/`). There is no per-user or per-session
  isolation; a second uploader will overwrite the first one's workspace.
- Build verification (`mvn compile`, `gradle compileJava`) executes inside the
  uploaded project. Maven and Gradle plugins declared in the project run
  arbitrary code at compile time. **Treat every uploaded archive as untrusted
  code that will execute on the host.** The default container runs as `root`
  with full network egress and only a 120 s timeout.
- LLM endpoints (`LLM_API_BASE`, `REMEDIATION_LLM_API_BASE`) are assumed to be
  reachable on the same host or trusted network. API keys are read from env
  and forwarded verbatim.

**What this means for safe operation.**

- Bind the API to `127.0.0.1` only. Do not expose it on a public interface
  without first adding an authenticating reverse proxy and per-user workspace
  isolation.
- Run the backend container in a sandboxed environment if you accept arbitrary
  uploads (firejail, nsjail, or a dedicated VM are reasonable starting points).
  The current `Dockerfile.backend` is not a sufficient sandbox by itself.
- Do not ingest source archives you have not personally vetted unless the
  build-verification path is disabled or sandboxed.
- Do not run remediation `mode="apply"` against codebases you do not control.
  The `dry_run` path is safe; the live-apply path mutates the workspace.

**What we explicitly do not claim.**

- Multi-tenancy. Multiple concurrent users share the same workspace and
  progress state.
- Production-grade authentication or authorization.
- Hermetic execution of arbitrary uploaded code. Maven plugin trust is
  inherited from the JVM build ecosystem.

If you intend to harden the service for any of these properties, treat that as
a separate engineering effort beyond the thesis artifact.

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
