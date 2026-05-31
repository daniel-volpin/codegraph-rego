# AGENTS

CodeGraph is a benchmark-backed JVM security/compliance framework. Its primary proof surface is **OWASP Benchmark**. Treat realistic apps as secondary workflow case studies.

Keep this file short. Detailed project context lives under `.opencode/project/`. Project-local skills and agents live under `.opencode/`.

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

- Python changes: run relevant `pytest` targets plus `ruff check`.
- Frontend changes: run `cd frontend && yarn build`.
- Benchmark-sensitive changes: run at least one smoke or focused benchmark command.
- Cite final results from files under `outputs/`.
