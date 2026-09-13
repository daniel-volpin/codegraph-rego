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
- Modular decoupled backend architecture:
  - `codegraph.ingestion`: AST extraction (`extraction.py`), Cypher batch writes (`persistence.py`), coordinator (`service.py`).
  - `codegraph.policy`: Boolean/arithmetic evaluation (`boolean_eval.py`), branch reduction (`conditional.py`), Cypher query builder (`graph_queries.py`), SARIF v2.1.0 exporter (`sarif.py`).
  - `codegraph.evaluation`: Confidence calibration and reliability bins (`calibration.py`), runtime coordinator (`remediation_runtime.py`).
  - `codegraph.remediation`: Multi-attempt retry loop (`attempts.py`), sandboxed verification & rollback (`apply_flow.py`).
- Production import standards:
  - Keep imports explicit, sorted, and strictly at the top of the file; avoid inline/on-the-fly imports inside function bodies.
  - Submodules must import from concrete source files rather than parent package barrels.
  - Package `__init__.py` barrels use PEP 562 lazy attribute loaders (`__getattr__`) to prevent circular import deadlocks during contract or registry initialization.
- Remediation supports both bounded single-method replacement and autonomous
  multi-turn agentic refactoring (`codegraph.remediation.agentic`). Every remediation
  candidate must satisfy the 3 invariant gates (JDT compilation, project test regression,
  and OPA policy clearance) in an isolated scratch worktree before any live apply.
  Dry runs must never mutate original source or the shared graph.
- LLM Transport and Tool-Calling Protocol:
  - Tool calling uses strongly typed OpenAI-compatible envelopes (`ToolDefinition`, `ToolCall`, `ChatCompletionResponse`).
  - `function.arguments` in tool calls must be serialized as valid JSON strings (e.g. `json.dumps(args)`), not raw Python dictionaries, when echoing tool calls back in multi-turn conversation messages.
  - Local MLX inference via LM Studio (`http://127.0.0.1:1234/v1`) enforces single-concurrency safety (`llm_max_concurrent_requests=1`, `llm_concurrency=1`) and generous timeouts (`llm_timeout_seconds=180.0`, `llm_queue_timeout_seconds=60.0`) to avoid Apple Silicon unified memory thrashing and premature request drops.
- Multi-Standard Policy Packs and Universal SAST (SARIF):
  - Pluggable policy packs are discovered automatically from `policy/packs/` (PCI-DSS 4.0, NIST SP 800-53, OWASP Top 10, ISO-27001).
  - External SAST reports in OASIS SARIF v2.1.0 format (`POST /policy/import/sarif`) are anchored against Neo4j AST `method_key` nodes and enter the same 3-gate agentic repair pipeline as native policy findings.
- Keep backend DTOs and `frontend/src/lib/schemas.ts` aligned.
  `frontend/src/lib/types.ts` re-exports derived types; do not duplicate them.
- Keep `policy/catalog.json`, Rego rules, OpenGrep rules, and
  `configs/benchmark/` aligned. Do not silently change control mappings or
  benchmark semantics.
- Detection engines are plugins, registry-routed. Each rule in
  `configs/benchmark/policy_registry.json` declares `evidence_source`:
  `opa` (Rego module under `policy/`) or `opengrep` (taint rule under
  `policy/opengrep/`, auto-discovered and imported through the SARIF bridge).
  Engines are registered once in `codegraph/policy/engines.py`; adding a rule
  means adding its definition plus a fixture, never new dispatch code.
  Anything that re-evaluates a finding must route by
  `evidence_source_for_rule_id`; rechecking with the wrong engine finds
  nothing and reads as "fixed". A missing engine fails rather than silently
  reducing coverage. Each engine also costs install weight and CI time, so it
  must earn its place on measured coverage — see
  `docs/architecture/2026-09-13-cpg-engine-evaluation.md` for an engine that
  was measured and rejected, and do not re-add one on intuition.
- Configuration is evidence, recorded in the graph. Ingestion writes
  `ConfigProperty` nodes for the analysed workspace; evaluation reads them from
  the active revision and never from the filesystem, because the analysed
  workspace is often temporary. A method is linked to a key by the parser's
  recorded argument literal, never by a source-text search, so an unresolvable
  key leaves the policy silent. Rego decides which values are unsafe; Python
  only assembles facts. Conflicting declarations are reported, not resolved.
  A finding means the configured value is unsafe, not that a deployment is
  vulnerable. See `docs/architecture/2026-09-13-configuration-facts.md`.
- Anything that re-evaluates a finding must be able to reproduce the evidence
  the finding used. A recheck that cannot fails closed and refuses; it never
  reports "fixed" from evidence it could not see.
- Detection evaluation runs per policy group (`run_benchmark_eval.py
  --categories`), and `compose_benchmark_eval.py` merges group outputs. The
  Overall row is recomputed from per-case fired rules under the union any-rule
  definition; never sum the per-category rows.
- Injection controls use dataflow taint analysis, not lexical matching.
  Do not reintroduce substring/co-occurrence heuristics for them: the
  retired Rego versions failed OWASP Benchmark's deliberate
  "looks tainted, isn't" cases. Known engine limits are cross-file taint
  and collection index-sensitivity; treat those as documented scope, not
  as bugs to paper over with pattern matching.
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
  `make policy-fmt` rewrites files. Run `make opengrep-test` for the taint
  rules; every rule under `policy/opengrep/` needs an annotated fixture in
  `tests/fixtures/opengrep/` asserting both a detection and a non-detection.
- Detection figures are a property of the engine configuration as well as the
  corpus. State which engines a run used when citing one.
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
- OPA findings, taint findings, successful compilation, and confidence scores
  do not prove behavioral equivalence or production safety. Safe refusal is a valid outcome;
  graph-based evidence is not full taint analysis or autonomous production repair.
- The recorded `0.9528` detection figure is qualified evidence: it predates
  audit POLICY-C1's removal of the `benchmarktest` corpus fingerprint and does
  not reproduce on the current baseline under its own matched config
  (measured `0.838` on its own matched config; the current full-corpus
  figure is `0.8591`). Cite it only with the caveat recorded in
  `docs/thesis_context.md`. **Open task:** the thesis prose still cites the
  unqualified figure and needs correcting; treat that as outstanding until the
  write-up is updated.
- Cite benchmark claims with artifact paths and provenance. Report exact evidence
  scope, skipped prerequisites, and remaining unknowns; distinguish wall-clock
  timings from aggregate worker timings and do not sum overlapping test packets.
- Handoffs identify branch/commit, actual PR URL or publishing blocker, and the
  next acceptance owner. Include the root trace ID when available; say unavailable
  rather than inventing one.
