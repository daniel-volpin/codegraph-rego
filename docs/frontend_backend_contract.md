# Frontend/Backend Contract (CodeGraph)

This document describes the API surface and the frontend/backend integration for CodeGraph.

## Backend API Surface

FastAPI entrypoint: `app.py`  
Routers: `api/routers/`  
Request/response models: `api/models/`

### `GET /health`
- Router: `api/routers/health.py`
- Response:
  - HTTP `200` when `neo4j`, `faiss_index`, `signature_map` are all true; else HTTP `503`.
  - Body:
    - `neo4j, faiss_index, signature_map, embedding_model, opa: boolean`
    - `details: object` (subsystem error strings)

### `POST /upload`
- Router: `api/routers/upload.py`
- Request: `multipart/form-data` with `file` (must be a `.zip`)
- Response:
  - HTTP `200`: `{ "status": string, "java_root": string|null }`
  - HTTP `400`/`500`: `{ "error": string }`

### `GET /upload/status`
- Router: `api/routers/upload.py`
- Response HTTP `200`:
  - `phase: string`
  - `message: string`
  - `progress: number` (0..100)
  - `complete: boolean`
  - `error?: string|null`
  - `updated_at: string` (UTC ISO)
  - `started_at?: string|null`
- State source: `codegraph/common/progress.py`

### `POST /search`
- Router: `api/routers/search.py`
- Request JSON: `{ "query": string }`
- Response:
  - HTTP `200`: `{ "matches": string[], "contexts": Array<Array<{ method: string, neighbors: object[] }>> }`
  - HTTP `400`/`500`: `{ "error": string }`

### `GET /policy/evaluate`
- Router: `api/routers/policy.py`
- Query params:
  - `max_bundles?: number`
  - `max_total_violations?: number`
  - `max_per_violation_id?: number`
  - `rule_ids?: string[]` (repeat the parameter to filter server-side to an explicit rule subset)
- Response:
  - HTTP `200` on success — object including at least `violations: Violation[]`
  - HTTP `500` on failure — `{ "error": string, ... }`
- Violation schema (from `codegraph/policy/integration.py`):
  - `violation_id: string`
  - `reason: string`
  - `severity: string`
  - `target_method: string`
  - `file_path: string`
  - `control_metadata: object|null`
  - `remediation?: object`
    - `supported: boolean`
    - `support_tier: "full" | "guarded" | "manual"`
    - `reason_code: string`
    - `strategy: string|null`
    - `preview_available: boolean`
    - `verify_available: boolean`
    - `ui_apply_mode: "dry_run"`
    - `rationale: string`
    - `safe_refusal_possible: boolean`
  - `evidence: object`

### `POST /policy/evaluate_with_llm`
- Router: `api/routers/policy.py`
- Request JSON: `{ "limit": number, "model"?: string|null, "rule_ids"?: string[]|null }`
- Response HTTP `200`: `{ "violations": Violation[], "enriched": object[] }`

### `GET /policy/catalog`
- Router: `api/routers/policy.py`
- Response HTTP `200`: `{ "controls": object[] }`
- Catalog source: `policy/catalog.json`

### `POST /policy/explain_one`
- Router: `api/routers/policy.py`
- Request JSON: `{ "violation_id": string, ... }` (full violation object)
- Response HTTP `200`:
  - `status: string`
  - `explanation?: string`
  - `explanation_structured?: { citation: string, why: string, fix: string }`
  - `model?: string|null`
  - `include_graph_context?: boolean`
  - `error?: string|null`

### `POST /policy/reviews`
- Router: `api/routers/policy.py`
- Request JSON: triage review record
- Response HTTP `200`: saved review confirmation

### `GET /policy/reviews`
- Router: `api/routers/policy.py`
- Query params: `violation_key`, `limit`
- Response HTTP `200`: list of saved reviews

### `POST /remediation/preview`
- Router: `api/routers/remediation.py`
- Request JSON: `{ "violation_id": string, "target_method"?: string|null, "file_path"?: string|null }`
- Response:
  - HTTP `200`: preview-only remediation result (no filesystem changes)
  - HTTP `400` when `status=INVALID`, `404` when `status=NOT_FOUND`, `500` when `status=ERROR`
- Implementation: `codegraph/remediation/service.py` → `preview_virtual_fix()`

### `POST /remediation/apply`
- Router: `api/routers/remediation.py`
- Request JSON: `{ "violation_id": string, "target_method"?: string, "file_path"?: string, "mode": "dry_run"|"apply", "max_attempts": number }`
- Response:
  - HTTP `200` for `status="OK"` and `status="FAIL"`
  - HTTP `500` for `status="ERROR"`
  - HTTP `400`/`404` for `status="INVALID"` / `status="NOT_FOUND"`
- Implementation: `codegraph/remediation/service.py` → `apply_fix()`
- Note: `status="FAIL"` is an application-level outcome (verification failed), not a transport error.

---

## Frontend API Usage

Base URL: read from `VITE_API_BASE_URL` env var; fallback `http://127.0.0.1:8000`.  
All API calls are centralised in `frontend/src/lib/api.ts`.

### Mapping Table

| Frontend function | Backend endpoint | Notes |
|---|---|---|
| `uploadZip` | `POST /upload` | Polls `/upload/status` while processing |
| `fetchUploadStatus` | `GET /upload/status` | 1s polling while `complete: false` |
| `fetchHealth` | `GET /health` | 15s polling; renders per-subsystem booleans |
| `searchCode` | `POST /search` | JSON body `{"query": string}` |
| `evaluatePolicies` | `GET /policy/evaluate` | Supports repeated `rule_ids` query params for benchmark/demo-focused server-side filtering |
| `evaluatePoliciesWithLLM` | `POST /policy/evaluate_with_llm` | JSON body `{"limit", "model", "rule_ids"}` |
| `fetchPolicyCatalog` | `GET /policy/catalog` | Renders catalog entries |
| `explainOne` | `POST /policy/explain_one` | Single-violation LLM explanation |
| `saveReview` / `fetchReviews` | `POST`/`GET /policy/reviews` | Triage review persistence |
| `previewRemediation` | `POST /remediation/preview` | Virtual fix; no disk writes |
| `applyRemediation` | `POST /remediation/apply` | Frontend hardcodes `mode="dry_run"` |

Notes:
- The frontend should use `violation.remediation` metadata to decide whether automatic remediation actions are available.
- The Policy page persists a view preset in local storage. `Framework demo focus` sends the benchmark-aligned `rule_ids` set to the backend instead of filtering findings only on the client.
- Automatic remediation is intentionally tiered:
  - `full`: bounded auto-fix and verify paths are available
  - `guarded`: the UI should explain that `NO_FIX` is a valid safe outcome
  - `manual`: explanation-first/manual review only
