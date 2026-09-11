# Frontend/Backend Contract (CodeGraph)

This document describes the HTTP API surface and the frontend integration patterns CodeGraph relies on.

## Boundary primer

- Backend FastAPI entrypoint: `app.py` (calls `codegraph/app.py:create_app`).
- Routers: `api/routers/`.
- Request/response models: `api/models/`.
- Frontend HTTP layer: `frontend/src/lib/api.ts`.
- Wire-shape source of truth: **`frontend/src/lib/schemas.ts`** (Zod). Types in `frontend/src/lib/types.ts` are auto-derived re-exports — do not edit them by hand.
- Every API call funnels through one `parseApiResponse<S>(response, schema)` helper:
  - The schema's `.safeParse(payload)` is the only gate. If it succeeds the result is returned regardless of HTTP status (this is what lets structured-error envelopes on 4xx — e.g. `status: "INVALID"` from remediation — flow through as data instead of throwing).
  - Otherwise, `!response.ok` → `ApiError(message, status, payload)`.
  - Otherwise (200 with a non-matching shape) → `SchemaValidationError(zodError, payload)`. This catches real backend/frontend drift instead of silently rendering `"—"` everywhere.
- Every API request now carries a W3C `traceparent` header (browser OpenTelemetry `FetchInstrumentation` → FastAPI `FastAPIInstrumentor`), and every response carries an `X-Request-Id` header echoed by the backend.

## Backend API Surface

### `GET /healthz`
- Router: `api/routers/health.py`
- Cheap liveness probe. No external I/O.

### `GET /readyz`
- Router: `api/routers/health.py`
- Deeper readiness check. Returns `503` with structured details when degraded.

### `GET /health`
- Router: `api/routers/health.py`
- Response:
  - HTTP `200` when `neo4j`, `faiss_index`, `signature_map` are all true; else HTTP `503`.
  - Body fields: `status`, `startup_ready`, `neo4j`, `graph_generation`, `faiss_index`, `signature_map`, `embedding_model`, `opa: boolean`; `startup: HealthStartupStatus`; `details: object`.
  - `graph_generation` requires matching active graph and retrieval-artifact revisions, not merely a reachable Neo4j server. Startup validates resources without automatically ingesting or changing the graph.
- Frontend schema: `HealthCheckResponseSchema`.

### `POST /upload`
- Router: `api/routers/upload.py`
- Request: `multipart/form-data` with `file` (must be a `.zip`).
- Behavior:
  - streams the archive to disk instead of buffering in memory
  - rejects archives exceeding configured size, entry-count, extraction-size, or compression-ratio limits
  - discovers all `src/main/java` roots in the uploaded workspace and ingests them in deterministic sorted order
  - allocates a per-request progress slot via `codegraph/common/progress.py:start_progress` and echoes its `request_id`
- Response:
  - HTTP `200`: `{ "status": string, "java_root": string|null, "java_roots": string[], "request_id": string|null }`
  - HTTP `4xx`/`5xx`: `{ "error": string }`
- Frontend schema: `UploadResponseSchema`.

### `GET /upload/status`
- Router: `api/routers/upload.py`
- Polling endpoint backing the SSE-fallback path on the client.
- Query params: `request_id?: string` (when omitted, the latest-started job is returned for back-compat).
- Response HTTP `200`:
  - `phase`, `message`, `progress` (0..100), `complete`, `updated_at`, `started_at?`, `error?`, `request_id?`
- State source: `codegraph/common/progress.py`.
- Frontend schema: `UploadStatusSchema`.

### `GET /upload/status/stream`
- Router: `api/routers/upload.py`
- Push-based Server-Sent Events stream of `UploadStatus` payloads.
- Query params: `request_id?: string` (same semantics as `/upload/status`).
- Response: `text/event-stream` with `Cache-Control: no-cache`, `X-Accel-Buffering: no`.
- Event types:
  - `event: status` — one per observed state change of the progress slot. Data is the same JSON shape as `/upload/status`.
  - `event: complete` — terminal event when `complete=true`. Data is the final status. The connection closes after a short grace.
  - Periodic `: heartbeat` SSE comment lines (ignored by `EventSource`) defeat proxy idle timeouts.
- Implementation note: writers are woken by `register_state_change_listener` in `progress.py` and cross the thread boundary via `loop.call_soon_threadsafe` — no per-stream polling timer.
- Frontend consumer: `frontend/src/hooks/useUploadStatusStream.ts` validates every payload through `UploadStatusSchema.safeParse` before writing to the React Query cache. Falls back to bounded polling on EventSource error.

### `POST /search`
- Router: `api/routers/search.py`
- Request JSON: `{ "query": string }`
- Response:
  - HTTP `200`: `{ "matches": string[], "contexts": Array<Array<{ method: string, neighbors: object[] }>> }`
  - HTTP `4xx`/`5xx`: `{ "error": string }`
- Frontend schema: `SearchResponseSchema`.

### `GET /policy/evaluate`
- Router: `api/routers/policy.py`
- Query params:
  - `max_bundles?: number`
  - `max_total_violations?: number`
  - `max_per_violation_id?: number`
  - `rule_ids?: string[]` (repeat the parameter to filter server-side to an explicit rule subset)
- Response:
  - HTTP `200` on success — `violations: Violation[]` plus scan metadata:
    - `evaluation.status: "complete" | "partial" | "failed"`
    - `evaluation.attempted_bundles`, `evaluation.evaluated_bundles`, `evaluation.failed_bundles`
    - `evaluation.omitted_findings`, `evaluation.excluded_findings`
    - `evaluation.truncated`, `evaluation.scope_limited`, `evaluation.rule_ids`
    - optional `failed_bundles[]`, `failed_bundle_count`, and top-level `truncated`/`limits` when limit filters are supplied
  - HTTP `5xx` on failure — `{ "error": string, ... }`.
- `complete` means all selected bundles were evaluated successfully, not exhaustive workspace or parser coverage. `scope_limited` records a configured bundle cap, not a measured omitted-bundle count. `omitted_findings` counts findings removed by result caps; `excluded_findings` counts findings excluded by rule filters.
- Violation schema (from `codegraph/policy/integration.py`, mirrored as `ViolationSchema`):
  - `violation_id: string` (also accepts `rule_id` for backward compatibility)
  - `method_key: string` is the required operational identity; `target_method: string` is the human-readable signature, alongside `file_path: string` and `severity: string`.
  - `reason: string` (also accepts `description`)
  - `code_snippet?: string`, `updated_source_code?: string`
  - `evidence?: { source_code?: string, source_sha256?: string|null, graph_context?: ..., vector_context?: ... }`
  - `source_sha256` is the captured whole-file hash from parser provenance, not a hash of the displayed method snippet. Missing raw source stays unavailable; masked policy input is not substituted as source evidence.
  - `remediation?: RemediationCapability` (optional; frontend supplies defaults when absent):
    - `supported: boolean`
    - `support_tier: "full" | "guarded" | "manual"`
    - `reason_code: string`
    - `strategy: string|null`
    - `preview_available: boolean`
    - `verify_available: boolean`
    - `ui_apply_mode: "dry_run"`
    - `rationale: string`
    - `safe_refusal_possible: boolean`
- Frontend schema: `PolicyEvaluateResponseSchema`. The Zod object is `.loose()` — unknown backend fields pass through, so the explain endpoint receives the full original violation when the client sends `violation.raw` back.

### `POST /policy/evaluate_with_llm`
- Router: `api/routers/policy.py`
- Request JSON: `{ "limit": number, "model"?: string|null, "max_bundles"?: number|null, "max_total_violations"?: number|null, "max_per_violation_id"?: number|null, "rule_ids"?: string[]|null }`
- Response HTTP `200`: the full `/policy/evaluate` payload plus `enriched: object[]`.
  - Important: explanation enrichment is capped by `limit`, but the returned `violations` list and `evaluation` metadata remain the full evaluated result (no explained-only truncation).

### `GET /policy/catalog`
- Router: `api/routers/policy.py`
- Response HTTP `200`:
  - `controls: object[]`
  - `rules: object[]`
  - `benchmark_categories: PolicyBenchmarkCategory[]`
  - `framework_demo_rule_ids: string[]`
- Runtime source: `configs/benchmark/policy_registry.json`
- Compatibility snapshots: `policy/catalog.json`, `policy/iso_rules.json`
- Frontend schema: `PolicyCatalogResponseSchema`.

### `POST /policy/explain_one`
- Router: `api/routers/policy.py`
- Request JSON: `{ "violation": Violation, "include_graph_context"?: boolean, "model"?: string|null }` (the full violation object is sent back as `violation.raw` from the frontend; the loose Zod schema guarantees no fields are stripped on the round-trip)
- Response HTTP `200` (or HTTP `4xx`/`5xx` with the same envelope — `parseApiResponse` accepts both because the schema matches):
  - `status: string`
  - `explanation?: string|null`
  - `explanation_structured?: { evidence_id?: string|null, citation: string, why: string, fix: string }|null`
  - `model?: string|null`
  - `include_graph_context: boolean`
  - `error?: string|null`
- Frontend schema: `PolicyExplainOneResponseSchema`.

### `POST /policy/reviews`
- Router: `api/routers/policy.py`
- Request JSON: triage review record.
- Response HTTP `200` (or HTTP `4xx`/`5xx` envelope): `PolicyReviewCreateResponseSchema`.

### `GET /policy/reviews`
- Router: `api/routers/policy.py`
- Query params: `violation_key?: string`, `limit?: number`.
- Response HTTP `200`: `PolicyReviewListResponseSchema` (`{ status, reviews: object[], error? }`).

### `POST /remediation/preview`
- Router: `api/routers/remediation.py`
- Request JSON: `{ "violation_id": string, "method_key": string, "file_path"?: string|null }`
- `method_key` must be nonempty. Signature-only and obsolete `target_method` request fields are rejected with HTTP `422`, not used as alternative selectors.
- Response:
  - HTTP `200`: preview-only remediation result (no filesystem changes)
  - HTTP `400` when `status="INVALID"`, `404` when `status="NOT_FOUND"`, `500` when `status="ERROR"` — in all three cases the JSON payload validates against `RemediationPreviewResponseSchema` so `parseApiResponse` returns the structured envelope instead of throwing.
- Implementation: `codegraph/remediation/service.py` → `preview_virtual_fix()`.
- Includes optional `confidence: RemediationConfidence` (score, band, thresholds, rationale) — the score subfield uses `.catch(null)` so an out-of-range value can't reject the entire response.

### `POST /remediation/apply`
- Router: `api/routers/remediation.py`
- Request JSON: `{ "violation_id": string, "method_key": string, "file_path"?: string, "mode": "dry_run"|"apply", "max_attempts": number }`
- `method_key` identifies the workspace revision, file, and JDT declaration. Display signatures cannot select a target.
- Response:
  - HTTP `200` for `status="OK"` and `status="FAIL"`
  - HTTP `500` for `status="ERROR"`
  - HTTP `400`/`404` for `status="INVALID"` / `status="NOT_FOUND"`
  - All three HTTP failure shapes still parse through `RemediationApplyResponseSchema` so the frontend renders the structured outcome.
- Implementation: `codegraph/remediation/service.py` → `apply_fix()`.
- Note: `status="FAIL"` is an application-level outcome (verification failed), not a transport error.
- The frontend hardcodes `mode="dry_run"` in `applyRemediation`.
- Dry runs compile and verify the same candidate bytes in isolated temporary workspaces. They do not write the original source or publish a shared graph revision.
- Cleanup metadata: `verification.cleanup.file_restored` reports source restoration after a failed apply, and `verification.cleanup.revision_published` records successful apply publication. Values are `true`/`false`, or `null` when no restoration or publication was required.
- Apply requires passing policy verification and an attempted, successful compilation. Temporary workspace cleanup and a final source-freshness check precede source writes and whole-workspace revision publication.

### `POST /remediation/agentic`
- Router: `api/routers/remediation.py`
- Request JSON: `{ "finding": object, "workspace_root"?: string|null, "max_turns"?: number, "model"?: string|null }`
- Response HTTP `200`: `AgenticRemediationResponseSchema` (`{ status, rule_id, method_key, target_method, workspace_root, modified_files, diff, verification, reason, iterations, turns_count, error? }`).
- Implementation: `codegraph/remediation/agentic/` → `AgenticRemediationService.remediate_finding()`.
- Executes an autonomous multi-turn agent in an `IsolatedWorktreeEnvironment` with multi-file refactoring, automatic import additions, and 3-gate invariant verification (Compilation + Test Suite Regression + OPA Policy Clearance).

---

## Frontend API Usage

- Base URL is resolved at runtime by `lib/runtimeConfig.ts` in this order: `window.__CODEGRAPH_CONFIG__.apiBaseUrl` (set by `bootstrapRuntimeConfig` from `/config.json`) → `<meta name="api-base">` → `VITE_API_BASE_URL` → `/api`.
- All calls are centralized in `frontend/src/lib/api.ts`. Every endpoint function accepts an optional `AbortSignal` parameter; React Query passes its own cancellation signal automatically for queries, and mutations construct per-call `AbortController`s that are aborted on unmount or on re-fire.

### Mapping Table

| Frontend function | Backend endpoint | Notes |
|---|---|---|
| `uploadZip` | `POST /upload` | Returns `request_id` for SSE / polling subscription |
| `fetchUploadStatus` | `GET /upload/status` | Polling fallback (5 s) when the SSE stream is unavailable |
| `useUploadStatusStream` (hook) | `GET /upload/status/stream` | Push-based SSE; schema-validates every frame; falls back to polling on EventSource error |
| `fetchHealth` | `GET /health` | 15 s polling; renders per-subsystem booleans |
| `searchCode` | `POST /search` | Mutation; per-call AbortController cancels previous in-flight searches |
| `evaluatePolicies` | `GET /policy/evaluate` | Supports repeated `rule_ids` query params for benchmark/demo-focused server-side filtering |
| `evaluatePoliciesWithLLM` | `POST /policy/evaluate_with_llm` | JSON body accepts `limit`, `model`, and optional evaluate caps (`max_bundles`, `max_total_violations`, `max_per_violation_id`, `rule_ids`); returns full findings + metadata plus `enriched` |
| `fetchPolicyCatalog` | `GET /policy/catalog` | Renders catalog entries |
| `explainPolicyViolationOne` | `POST /policy/explain_one` | 5 min timeout; per-row AbortController in `useExplainMutation` |
| `saveViolationReview` / `fetchViolationReviews` | `POST`/`GET /policy/reviews` | Triage review persistence |
| `previewRemediation` | `POST /remediation/preview` | Virtual fix; no disk writes; 5 min timeout |
| `applyRemediation` | `POST /remediation/apply` | Frontend hardcodes `mode="dry_run"`; 5 min timeout |
| `runAgenticRemediation` | `POST /remediation/agentic` | Autonomous multi-turn agent with 3-gate verification; 5 min timeout |

### Cache topology

- One React Query cache key per violation and per resource: `["policy", "explain", id]`, `["policy", "preview", id]`, `["policy", "apply", id]` (`frontend/src/hooks/usePolicyArtifacts.ts`). Mutations write only to the affected key; sibling rows do not re-render on each other's landings.
- The row `id` combines the rule ID and canonical `method_key`, so changing workspace revision does not reuse another revision's remediation result. Findings without a method key fail API/persisted-payload validation.
- Cross-component pending state is derived from `useIsMutating` predicate-matching on `ViolationRow.id` (`usePendingAction`), so a button in the table row and a button in the detail panel agree on "is this finding's remediation in flight?" without sharing local state.
- Persistent UI cache (the multi-MB OPA evaluation payload) lives in IndexedDB via `lib/persistence.ts` (`idb-keyval`), schema-versioned and re-validated through Zod on read.

### UI contract notes

- The frontend uses `violation.remediation` metadata to decide whether automatic remediation actions are available.
- The Policy page persists a view preset in `localStorage`. `Framework demo focus` sends the benchmark-aligned `rule_ids` set to the backend instead of filtering findings only on the client.
- Multi-module uploads remain a single active workspace. The Upload page surfaces all detected Java roots, and the Policy page can filter findings by module without introducing a separate project switcher.
- Automatic remediation is intentionally tiered:
  - `full`: bounded auto-fix and verify paths are available
  - `guarded`: the UI explains that `NO_FIX` is a valid safe outcome
  - `manual`: explanation-first / manual review only

### Distributed tracing

- The browser-side `WebTracerProvider` in `lib/tracing.ts` registers `FetchInstrumentation` scoped to the API origin (`buildApiOriginMatcher(getRuntimeApiBase())`). Every API request carries a W3C `traceparent` header; cross-origin third-party calls (e.g. LM Studio's own server) are intentionally not propagated.
- Backend `codegraph/app.py:create_app` already instruments the FastAPI app via `FastAPIInstrumentor`, so the incoming `traceparent` continues the span server-side. The `OTEL_*` and `VITE_OTEL_*` env vars (see top-level README and `frontend/README.md`) control the exporter.
