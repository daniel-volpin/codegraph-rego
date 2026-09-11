# Agent guide - CodeGraph

CodeGraph is a benchmark-backed JVM security/compliance framework. OWASP Benchmark
is the primary proof surface; realistic apps are secondary workflow case studies.
This file is the canonical, cross-agent operating guide.

## Read first

- `README.md` and `REPRODUCIBILITY.md`: setup, runtime requirements, configuration,
  and runnable evaluation commands.
- `docs/frontend_backend_contract.md`: API/SPA contracts.
- `copilot-context/benchmark.md` and `docs/thesis_context.md`: control mappings,
  evidence anchors, support tiers, and scientific claim limits.
- `docs/architecture/2026-09-11-backend-modernization-roadmap.md`: migration
  decisions and acceptance boundaries. Historical milestones are not live status.

## Architecture and invariants

- Keep HTTP adapters in `api/` thin; domain logic belongs in `codegraph/`.
  Use `codegraph.config.settings`, typed helpers, explicit outcomes, and logging.
- Eclipse JDT is the sole Java parser. Its wire contract is
  `codegraph/java/models.py`; its adapter source is `tools/java-parser/`.
  Surface diagnostics; never add an alternate parser or guessed-range fallback.
- Graph-backed operations select canonical `method_key` identities, not display
  signatures. Source-only selectors must match exact declaring types/overloads.
- Preserve raw source bytes, verified native byte ranges, and captured source
  hashes. Missing or stale provenance must refuse an edit, not trigger a lookup
  or source-text fallback.
- Graph revisions are immutable. Read the active revision; publish whole
  workspaces and use predecessor receipts for conditional rollback. Incompatible
  graph/index generations require an explicit rebuild, not compatibility reads.
- Remediation must compile, verify, and write the same candidate bytes. Dry runs
  must not mutate original source or the shared graph. Finish temporary cleanup
  and recheck source freshness before apply/publication; skipped builds or
  non-passing verification cannot become success.
- Keep backend DTOs and `frontend/src/lib/schemas.ts` aligned.
  `frontend/src/lib/types.ts` re-exports derived types; do not duplicate them.
- Keep `policy/catalog.json`, Rego rules, and `configs/benchmark/` aligned.
  Do not silently change control mappings or benchmark semantics.
- Explanation uses structured `Citation / Why / Fix`; remediation uses
  `decision`, `replacement_method_lines`, and `reason`. Models propose;
  deterministic validation owns acceptance. Malformed output is an explicit
  failure, not an invitation to repair it with parser hacks.

## Runtime and dependencies

- Read `.python-version`, manifests, lockfiles, the adapter POM, and
  `REPRODUCIBILITY.md` rather than copying versions from old session notes.
- Use the project's supported interpreter and locked dependencies. On shared
  hosts, isolate review environments; do not replace an active worker's runtime
  or alter global tools to satisfy a local check.
- Build the trusted adapter with `make java-parser-build` before native parser
  checks. Missing tooling must be reported, not hidden by mocks or a fallback.
- For upgrades, check upstream runtime/peer constraints and affected APIs.
  Prefer current compatible releases; neither force incompatible transitive
  overrides nor retain arbitrary old caps just to make an audit look clean.
  Cover actual SDK error and cleanup types when changing transports.

## Workflow and delegation

- Inspect branch/worktree state first; preserve unrelated edits. Use a feature
  branch and a reviewable PR, never a direct push to `main`.
- Keep small tasks inline. For substantial independent work, assign bounded
  ownership, frozen interfaces, failure cases, and targeted acceptance commands.
  Prefer a lower-cost capable worker; reserve expensive models for difficult
  reasoning and integration.
- Workers implement, test, and return one result packet. The lead reviews
  integration once; further review addresses concrete findings or unresolved risk.
- Do not send status-only messages that restart completed workers. Reuse evidence
  when its source/runtime scope is unchanged; rerun affected callers after
  contract changes, not unrelated expensive suites after every status update.
- Stop at the agreed handoff boundary. Deferred runtime, benchmark, or product
  work is not a reason to delay a coherent source PR indefinitely.

## Validation

- Python: select affected paths for `uv run python -m pytest -q`, then run
  `uv run ruff check .`. Group related callers; escalate when failures warrant it.
- Policy: `make policy-check` with the pinned OPA on `PATH`. This is check-only;
  `make policy-fmt` rewrites files.
- Frontend: `cd frontend && yarn lint && yarn test && yarn build`.
  Preserve file isolation and automatic test discovery when optimizing the runner.
- Exercise the real public path. Mock external boundaries, not both orchestration
  and the behavior being asserted. Use valid Java fixtures and real JDT
  identities/hashes for source-editing regressions; fix stale fixtures rather
  than weakening parser or provenance checks.
- Benchmark-sensitive changes need a focused smoke/evaluation run in disposable
  state. Full model, container, and application E2E acceptance is separate from
  unit results and successful test collection.
- On the home server, instruction/harness changes require `make preflight` and
  `make benchmark-compare` in `../home-server-docs`; do not update baselines to
  erase regressions. Elsewhere, report unavailable host-specific gates.

## Safety, publishing, and evidence

- Never inspect, print, or commit protected credentials, real `.env` files, or
  private keys. Do not overwrite historical artifacts under `outputs/`.
- Push, merge, deployment, shared-data mutation, and paid model calls require
  explicit authorization. Delegation grants no extra authority. On the home
  server, follow its standing contract and
  `../home-server-docs/generated/AGENT_PLATFORM_CONTEXT.md`.
- Confirm the actual remote before choosing GitHub or Forgejo tooling. Use
  official CLI diagnostics, not credential-file inspection. Distinguish missing
  tools, authentication, and permission scopes; report the actual rejection.
  Request authorization for missing scopes instead of dropping workflow changes
  or granting persistent broad permissions.
- OPA findings, successful compilation, and confidence scores do not prove
  behavioral equivalence or production safety. Safe refusal is a valid outcome;
  graph-based evidence is not full taint analysis or autonomous production repair.
- Cite benchmark claims with artifact paths and provenance. Report exact evidence
  scope, skipped prerequisites, and remaining unknowns; distinguish wall-clock
  timings from aggregate worker timings and do not sum overlapping test packets.
- Handoffs identify branch/commit, actual PR URL or publishing blocker, and the
  next acceptance owner. Include the root trace ID when available; say unavailable
  rather than inventing one.
