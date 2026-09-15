# CodeGraph Frontend

React + TypeScript + Vite client for the local CodeGraph workbench.

## Run

From the repository root, `make dev` starts the backend and frontend together. Frontend-only development:

```bash
cd frontend
yarn install
yarn dev
```

The Vite server listens on <http://127.0.0.1:5173> by default and proxies `/api` to the backend development target.

## Routes

`src/App.tsx` owns the user routes:

- `/` — workspace overview
- `/upload` — project ingestion
- `/policy` — policy findings, evidence, explanations, and remediation
- `/settings` — runtime/observability settings

## Contract

- `src/lib/api.ts` owns HTTP transport.
- `src/lib/schemas.ts` owns Zod validation for backend payloads.
- TanStack Query owns server state.
- Zustand is used for local client state where needed.
- API schema changes must update the backend model and matching Zod schema together. See [`../docs/frontend_backend_contract.md`](../docs/frontend_backend_contract.md).

## Environment

Browser-visible variables are declared in `src/env.d.ts`:

| Variable | Purpose |
| --- | --- |
| `VITE_API_BASE_URL` | API base override |
| `VITE_OTEL_EXPORTER_OTLP_ENDPOINT` | browser OTLP/HTTP trace exporter |
| `VITE_OTEL_DISABLED` | disables browser tracing when set accordingly |

The Vite development proxy may also be configured by the repository's Vite configuration. Treat `vite.config.ts` as the source of truth for its current environment variable and default target.

## Validation

```bash
yarn lint
yarn test
yarn build
```

Playwright tests are available separately:

```bash
yarn test:e2e
```

They require the services expected by the selected end-to-end scenario.

## Structure

```text
src/
  components/  reusable UI and feature components
  hooks/       query and UI hooks
  lib/         API client, schemas, runtime config, persistence, observability
  pages/       route-level screens
  store/       local client state
  test/        shared test support
```

Keep this README focused on frontend development. Product behavior and exact API payloads belong in source schemas and tests rather than duplicated prose.
