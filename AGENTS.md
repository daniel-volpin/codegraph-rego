# AGENTS

CodeGraph is a benchmark-backed security/compliance framework for JVM code. Its primary thesis and product proof surface is **OWASP Benchmark**, not an uploaded demo app. Treat realistic apps as secondary workflow case studies.

Keep this file short, explicit, and current. Prefer benchmark evidence, canonical configs, and verified behavior over prototype shortcuts.

## Current Ground Truth

- Primary workflow: ingest Java -> Neo4j graph -> OPA/Rego policy evaluation -> structured explanation -> bounded remediation -> re-verification.
- Canonical benchmark configs live in `configs/benchmark/`.
- Root-level `configs/benchmark_selection*.json` files are legacy compatibility shims. Do not use them as defaults.
- Benchmark-first categories currently in scope:
  - `CWE-22` -> `ISO-A.8-PATH-TRAVERSAL`
  - `CWE-78` -> `ISO-A.8-CMD-INJECTION`
  - `CWE-89` -> `ISO-A.8-SQL-INJECTION`
  - `CWE-90` -> `ISO-A.8-LDAP-INJECTION`
  - `CWE-327` -> `ISO-A.10-WEAK-CRYPTO`
  - `CWE-328` -> `ISO-A.10-WEAK-HASH`
  - `CWE-330` -> `ISO-A.10-WEAK-RANDOM`
  - `CWE-643` -> `ISO-A.8-XPATH-INJECTION`
- Remediation support tiers:
  - `full`: weak hash, weak random
  - `guarded`: weak crypto
  - `manual`: SQLi, path traversal, command injection, LDAP injection, XPath injection, access/logging rules

## Repository Focus

- `codegraph/`: backend domain logic
- `api/routers/`: FastAPI HTTP boundary
- `policy/`: Rego rules and catalog
- `frontend/`: React/Vite UI
- `configs/benchmark/`: canonical benchmark configs
- `docs/`: contract, prompting, thesis context
- `tests/`: pytest coverage

## Engineering Rules

- Use `codegraph.config.settings`; do not read env vars ad hoc.
- Keep Neo4j access centralized via `codegraph.db`.
- Keep routers thin; business logic belongs under `codegraph/`.
- Keep `policy/catalog.json` aligned with Rego rules.
- Prefer typed helpers, dataclasses/Pydantic models, and explicit return objects.
- Use `logging`, not `print`.
- Avoid frontend/backend contract drift; update `frontend/src/lib/types.ts` when API payloads change.

## Benchmark and Thesis Rules

- Benchmark evidence matters more than intuition. When changing benchmark behavior, run a targeted smoke or medium evaluation.
- Do not silently change benchmark semantics or control mappings.
- Prefer new canonical configs over mutating old thesis-era ones.
- Keep outputs reviewable and traceable by purpose; do not overwrite prior evidence casually.
- For thesis claims, be precise:
  - broad detection and explanation coverage
  - bounded remediation support
  - safe refusal is valid behavior
- The compact project source of truth lives under `docs/project/`.

## LLM Rules

- Explanation uses structured output and should yield concise `Citation / Why / Fix`.
- Remediation uses a structured contract and currently expects:
  - `decision`
  - `replacement_method_lines`
  - `reason`
- Do not fall back to fragile parser tricks as the primary solution.
- Explanation and remediation may use different models. Prefer remediation-specific settings when testing code generation quality.
- Current LM Studio setup is the expected local runtime. Prefer model-specific tuning over widening parser hacks.

## Tooling

- Backend package manager: `uv`
- Frontend package manager: `yarn`
- Backend lint/format: `ruff`
- Frontend build check: `cd frontend && yarn build`
- Fast syntax check: `python -m compileall codegraph api scripts/evaluation`

## Default Validation

- Python changes: run relevant `pytest` targets plus `ruff check`.
- Frontend changes: run `cd frontend && yarn build`.
- Benchmark-sensitive changes: run at least one smoke or focused benchmark command.
- When discussing final results, cite output files under `outputs/`.

## Canonical Runs

- Detection baseline:
  - `run_benchmark_eval.py --config configs/benchmark/baseline.json`
- Medium benchmark breadth:
  - `run_benchmark_eval.py --config configs/benchmark/multicat_medium.json`
- Full selected-category benchmark:
  - `run_benchmark_eval.py --config configs/benchmark/multicat_full.json`
- Explanation full:
  - `run_explanation_eval.py --config configs/benchmark/multicat_full.json`
- Supported remediation medium:
  - `run_remediation_eval.py --config configs/benchmark/remediation_supported_medium.json`

## Documentation Discipline

- Keep `README.md` and `REPRODUCIBILITY.md` aligned with current defaults.
- Keep `docs/project/` aligned with the latest benchmark evidence and current support matrix.
- If architecture or contracts change, update the corresponding docs in `docs/`.
- In summaries and PRs, report:
  - what changed
  - what was tested
  - what is still bounded or unresolved
