# CodeGraph — Claude Project Context

## What This Is

MSc Software Engineering thesis project (UvA, Daniel Volpin). A neurosymbolic compliance framework that:
1. Ingests JVM code into Neo4j (graph-based code understanding)
2. Evaluates ISO 27001 controls via OPA/Rego policy rules
3. Generates grounded LLM explanations with structured evidence citations
4. Performs bounded, confidence-gated remediation with build re-verification

Primary proof surface: **OWASP Benchmark v1.2** (2,740 Java test cases).
Real-world apps (JHipster, PetClinic) are secondary case studies only — not the primary evidence surface.

## Branch / Worktree Setup

- `main` lives at `.claude/worktrees/focused-chaum/` (git worktree — do not `git checkout main` from the feature branch dir)
- Active development branch: `feat/remediation-redesign-step-7-rework`
- Always run thesis-grade benchmark commands from the `main` worktree

## Authoritative Thesis Evidence (2026-03-22)

| Component | Directory | Headline |
|---|---|---|
| Detection | `outputs/thesis_final_detection_full/` | P=R=F1=0.953 · 222 TP · 8 CWEs · 454 cases |
| Explanation | `outputs/thesis_final_explanation_full/` | Citation@Context=0.9955 · 222 TPs |
| Remediation | `outputs/thesis_final_remediation_v2/` | 25/25 OK · fix+build 1.000 · Brier=0.006 |

Historical runs in `outputs/` are preserved but must not be cited as current results.

## Evaluation Commands (run from main worktree, `source .env` first)

```bash
# Detection (~1 min, no LLM)
.venv/bin/python run_benchmark_eval.py \
  --config configs/benchmark/multicat_full.json \
  --mapping configs/benchmark/policy_registry.json \
  --output-dir outputs/thesis_final_detection_full \
  --reset-neo4j

# Explanation (~90 min, requires LLM)
LLM_CONCURRENCY=1 .venv/bin/python run_explanation_eval.py \
  --config configs/benchmark/multicat_full.json \
  --mapping configs/benchmark/policy_registry.json \
  --output-dir outputs/thesis_final_explanation_full \
  --evidence-mode lean --llm-max-tokens-eval 192 --reset-neo4j

# Remediation (~2 hrs, requires LLM)
.venv/bin/python run_remediation_eval.py \
  --config configs/benchmark/remediation_supported_medium.json \
  --mapping configs/benchmark/policy_registry.json \
  --output-dir outputs/thesis_final_remediation_v2 \
  --sample-size 60 --reset-neo4j
```

## Services Required

| Service | Default | Purpose |
|---|---|---|
| Neo4j 5.x | `bolt://127.0.0.1:7687` | Code graph storage |
| OPA | `PATH` | Rego policy evaluation |
| LM Studio | `http://localhost:1234/v1` | Explanation + remediation LLM |

Explanation model: `qwen3.5-9b-mlx` · Remediation model: `qwen/qwen3-coder-30b`
Enable LM Studio `Auto-Evict` — CodeGraph sends per-request TTL hints.

## Tests and Linting

```bash
.venv/bin/ruff check .
UV_CACHE_DIR=/tmp/uv-cache uv run python -m pytest -q
cd frontend && yarn build
```

Use `.venv/bin/python -m pytest`, not system `python3 -m pytest` (venv has all deps).

## Key Architecture

- `codegraph/policy/runtime/opa.py` — `build_violation_response()` assembles evidence bundles; single authoritative point for violation dicts
- `codegraph/policy/runtime/bundles.py` — `build_evidence_bundle()` populates graph context, taint paths, FAISS vectors
- `codegraph/remediation/apply_flow.py` — confidence gate + `PolicyStateTrace` before/after capture
- `codegraph/remediation/confidence.py` — sigmoid-based `assess_remediation_confidence()`, bands: apply/review/abstain
- `codegraph/evaluation/remediation_runtime.py` — `build_confidence_calibration()` writes Brier/ECE to `confidence_calibration.json`
- `policy/catalog.json` — 10 controls: 8 active CWE categories + access control + logging
- `configs/benchmark/` — canonical benchmark configs; never switch config families silently

## Remediation Scope

| Tier | Categories |
|---|---|
| `full` | ISO-A.10-WEAK-HASH, ISO-A.10-WEAK-RANDOM |
| `guarded` | ISO-A.10-WEAK-CRYPTO (`NO_FIX` is a valid safe outcome) |
| `manual` | All 5 injection families + access-control + logging |

## Thesis Language Constraints

- Say **"graph-based code understanding"** or **"graph-structured evidence"** — not "Code Property Graph", "CPG", "control-flow graph", or "data-dependency graph" (none of these are implemented)
- Multi-hop BFS taint is an approximation over CALLS edges — not formal taint analysis
- Remediation is bounded and `dry_run` verified — not production autonomous repair
- `Citation@NoContext=0.000` is the expected ablation lower-bound — not a failure

## Output Artifact Conventions

- `outputs/` is gitignored — no git history for run outputs
- Each eval script is self-contained (does its own Neo4j ingest + OPA eval)
- `--reset-neo4j` is required for reproducible runs
- `progress.json` in each output dir tracks live status during long runs
- Confidence calibration only populates on runs after PR #81 landed on main

## Important Docs

- `REPRODUCIBILITY.md` — shortest path to rerun the full pipeline
- `.opencode/project/benchmark_latest.md` — current authoritative numbers
- `.opencode/project/runbook.md` — output locations and citation guidance
- `.opencode/project/open_issues.md` — known bounded risks and what not to overclaim
- `docs/thesis_context.md` — thesis framing and terminology constraints
