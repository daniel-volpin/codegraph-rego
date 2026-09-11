# AGENTS

CodeGraph is a benchmark-backed JVM security/compliance framework. Its primary proof surface is **OWASP Benchmark**. Treat realistic apps as secondary workflow case studies.

Keep this file short. Detailed project context lives in `CLAUDE.md` and `copilot-context/benchmark.md`.

## Core Ground Truth

- Primary workflow: ingest Java -> Neo4j graph -> OPA/Rego policy evaluation -> structured explanation -> bounded remediation -> re-verification.
- Canonical benchmark configs live in `configs/benchmark/`.
- Current benchmark scope:
  - `CWE-22` -> `ISO-A.8-PATH-TRAVERSAL`
  - `CWE-78` -> `ISO-A.8-CMD-INJECTION`
  - `CWE-89` -> `ISO-A.8-SQL-INJECTION`
  - `CWE-90` -> `ISO-A.8-LDAP-INJECTION`
  - `CWE-327` -> `ISO-A.10-WEAK-CRYPTO`
  - `CWE-328` -> `ISO-A.10-WEAK-HASH`
  - `CWE-330` -> `ISO-A.10-WEAK-RANDOM`
  - `CWE-643` -> `ISO-A.8-XPATH-INJECTION`
- Remediation tiers:
  - `full`: weak hash, weak random
  - `guarded`: weak crypto
  - `manual`: injection families and access/logging rules

## Engineering Rules

- Use `codegraph.config.settings`; do not read env vars ad hoc.
- Keep routers thin and business logic under `codegraph/`.
- Keep `policy/catalog.json` aligned with Rego rules.
- Prefer typed helpers and explicit return objects.
- Use `logging`, not `print`.
- Avoid frontend/backend contract drift; update `frontend/src/lib/schemas.ts` (Zod schemas) when API payloads change. Types in `frontend/src/lib/types.ts` are auto-derived re-exports — no hand-maintained type definitions live there.

## Development Model Budget

- Reserve Astra for planning, coordination, and concise integration reviews; prefer a non-Astra model for implementation.
- Follow the shared lean delegation policy in `../home-server-docs/generated/AGENT_PLATFORM_CONTEXT.md` when working on the home server. Repo guidance never overrides active higher-priority restrictions.
- Use bounded roadmap packets with explicit file ownership and frozen interfaces; serialize shared ingestion, policy, and remediation contracts. Keep tiny changes inline.
- Workers implement and run targeted tests, fixing failures before handing off the diff, results, and blockers. The lead performs one integration review, not a repeat investigation; further review targets concrete findings or high-risk changes.
- Put failure boundaries in the dispatch: stale inputs, repeated calls after failure, cancellation, and concurrent publication where relevant. Exercise the real public path; mock external dependencies, not both the coordinator and the behavior under test. Include affected callers in the same targeted run to expose import/cache interactions. Handoffs distinguish demonstrated behavior from untested assumptions.
- Preserve canonical thesis artifacts and approval gates. Development-agent delegation does not authorize paid CodeGraph model calls, live graph changes, push, merge, or deployment.

## Benchmark Rules

- Benchmark evidence matters more than intuition.
- Do not silently change benchmark semantics or control mappings.
- Prefer canonical configs under `configs/benchmark/`.
- Keep outputs reviewable and traceable by purpose.
- Be precise in claims:
  - broad detection and explanation coverage
  - bounded remediation support
  - safe refusal is valid behavior

## LLM Rules

- Explanation uses structured output with concise `Citation / Why / Fix`.
- Remediation uses a structured contract with:
  - `decision`
  - `replacement_method_lines`
  - `reason`
- Do not use fragile parser hacks as the primary remediation strategy.
- Explanation and remediation may use different models.

## Validation Defaults

- Python changes: run relevant `pytest` targets plus `ruff check .`.
- Policy (`policy/`) changes: run `make policy-check` (check-only: `opa check --strict` plus format-drift gate; `make policy-fmt` rewrites formatting).
- Frontend changes: run `cd frontend && yarn lint && yarn test && yarn build`.
- Benchmark-sensitive changes: run at least one smoke or focused benchmark command.
- Cite final results from files under `outputs/`.
