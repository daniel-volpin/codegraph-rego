# Frontend/Backend Contract (CodeGraph)

This document is derived from the current repository code (not assumptions).

## Backend API Surface

FastAPI entrypoint: `/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/app.py`
Routers: `/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/api/routers/`
Request/response models (partial): `/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/api/models/validation.py`

### `GET /health`
- Router: `/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/api/routers/health.py`
- Response:
  - HTTP `200` when `neo4j`, `faiss_index`, `signature_map` are all true; else HTTP `503`.
  - Body:
    - `neo4j, faiss_index, signature_map, embedding_model, opa: boolean`
    - `details: object` (subsystem error strings)

### `POST /upload`
- Router: `/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/api/routers/upload.py`
- Request: `multipart/form-data` with `file` (must be a `.zip`)
- Response:
  - HTTP `200`: `{ "status": string, "java_root": string|null }`
  - HTTP `400`/`500`: `{ "error": string }`

### `GET /upload/status`
- Router: `/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/api/routers/upload.py`
- Response HTTP `200`:
  - `phase: string`
  - `message: string`
  - `progress: number` (0..100)
  - `complete: boolean`
  - `error?: string|null`
  - `updated_at: string` (UTC ISO)
  - `started_at?: string|null`
- State source: `/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/codegraph/common/progress.py`

### `POST /search`
- Router: `/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/api/routers/search.py`
- Request JSON: `{ "query": string }`
- Response:
  - HTTP `200`: `{ "matches": string[], "contexts": Array<Array<{ method: string, neighbors: object[] }>> }`
  - HTTP `400`/`500`: `{ "error": string }`

### `GET /policy/evaluate`
- Router: `/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/api/routers/policy.py`
- Response:
  - HTTP `200` on success: object including at least `violations: Violation[]`
  - HTTP `500` on failure: `{ "error": string, ... }`
- Actual violation schema is produced by `/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/codegraph/policy/integration.py`:
  - `violation_id: string`
  - `reason: string`
  - `severity: string`
  - `target_method: string`
  - `file_path: string`
  - `control_metadata: object|null`
  - `evidence: object`

### `POST /policy/evaluate_with_llm`
- Router: `/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/api/routers/policy.py`
- Request JSON: `{ "limit": number, "model"?: string|null }`
- Response HTTP `200`:
  - `{ "violations": Violation[], "enriched": object[] }`

### `GET /policy/catalog`
- Router: `/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/api/routers/policy.py`
- Response HTTP `200`: `{ "controls": object[] }`
- Catalog source: `/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/policy/catalog.json`

### `POST /remediation/preview`
- Router: `/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/api/routers/remediation.py`
- Request JSON:
  - `{ "violation_id": string, "target_method"?: string|null, "file_path"?: string|null }`
- Response:
  - HTTP `200`: preview-only remediation result
  - HTTP `400` when `status=INVALID`, `404` when `status=NOT_FOUND`, `500` when `status=ERROR`
- Implementation: `/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/codegraph/remediation/service.py` (`preview_virtual_fix`)
- Important semantics: preview is virtual and does not modify files.

### `POST /remediation/apply`
- Router: `/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/api/routers/remediation.py`
- Request JSON:
  - `{ "violation_id": string, "target_method"?: string, "file_path"?: string, "mode": "dry_run"|"apply", "max_attempts": number }`
- Response:
  - HTTP `200` for `status="OK"` and `status="FAIL"`
  - HTTP `500` for `status="ERROR"`
  - HTTP `400`/`404` for `status="INVALID"` / `status="NOT_FOUND"`
- Implementation: `/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/codegraph/remediation/service.py` (`apply_fix`)
- Contract note: `status="FAIL"` is an application-level outcome (verification failed), not a transport error.

## Frontend API Usage

Base URL:
- `/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/frontend/src/lib/api.ts`
- `VITE_API_BASE_URL` with fallback `http://127.0.0.1:8000`

Frontend calls (centralized in):
- `/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/frontend/src/lib/api.ts`

### Mapping table

| Frontend | Backend | Notes |
|---|---|---|
| `uploadZip` in `/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/frontend/src/lib/api.ts` used by `/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/frontend/src/pages/UploadPage.tsx` | `POST /upload` | Polls `/upload/status` while processing |
| `fetchUploadStatus` in `/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/frontend/src/lib/api.ts` used by `/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/frontend/src/pages/UploadPage.tsx` | `GET /upload/status` | 1s polling while incomplete |
| `fetchHealth` in `/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/frontend/src/lib/api.ts` used by `/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/frontend/src/components/HealthStatus.tsx` | `GET /health` | 15s polling; UI currently shows booleans only |
| `searchCode` in `/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/frontend/src/lib/api.ts` used by `/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/frontend/src/pages/SearchPage.tsx` | `POST /search` | JSON body `{query}` |
| `evaluatePolicies` in `/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/frontend/src/lib/api.ts` used by `/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/frontend/src/pages/PolicyPage.tsx` | `GET /policy/evaluate` | Violations are rendered using backend `violation_id/reason/...` fields |
| `evaluatePoliciesWithLLM` in `/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/frontend/src/lib/api.ts` used by `/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/frontend/src/pages/PolicyPage.tsx` | `POST /policy/evaluate_with_llm` | JSON body `{limit,model}` |
| `fetchPolicyCatalog` in `/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/frontend/src/lib/api.ts` used by `/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/frontend/src/pages/PolicyPage.tsx` | `GET /policy/catalog` | Renders catalog entries |
| `previewRemediation` in `/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/frontend/src/lib/api.ts` used by `/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/frontend/src/pages/PolicyPage.tsx` | `POST /remediation/preview` | Preview-only remediation |
| `applyRemediation` in `/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/frontend/src/lib/api.ts` used by `/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/frontend/src/pages/PolicyPage.tsx` | `POST /remediation/apply` | Frontend forces `mode="dry_run"` currently |

## README Drift (Current Behavior vs Docs)
- `/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/README.md` describes `/search` as a form field request; the code uses a JSON request body.
- `/Users/pnl11e4o/Documents/Academic/Thesis Project/Code/codegraph/README.md` describes `/policy/evaluate_with_llm` using query parameters; the code uses a JSON request body.

## Verification Notes (Local)
- Backend:
  - Ran `.venv/bin/python3 -m compileall codegraph api` (success)
  - Ran `.venv/bin/python3 -m unittest discover -s tests -p "test_*.py"` (success)
- Frontend:
  - `npm run build` failed on this machine with:
    - `Error: Cannot find module @rollup/rollup-darwin-arm64` (during `vite build`)
    - Node: `v24.13.1`
  - Safe workaround path (no dependency upgrades intended):
    - `rm -rf node_modules`
    - `npm ci`
    - re-run `npm run build`
  - If that still fails, treat it as an environment/tooling issue (do not upgrade dependencies as part of this fix scope).

