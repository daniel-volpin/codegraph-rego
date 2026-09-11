# CodeGraph Frontend

This Vite + React (TypeScript) client surfaces the neurosymbolic security and compliance evaluation workbench for CodeGraph, designed according to the **Impeccable** design system (`Operate` register):

- **Upload & Ingest (`/upload`)**: Upload Java projects and monitor real-time SSE extraction into the code graph.
- **Policy Workbench & Case Dossier (`/policy`)**: Evaluate OWASP Top 10 & ISO 27001 policy rules with OPA (RQ1), inspect graph-grounded evidence citations (RQ2), and execute bounded AI remediation with dry-run compiler & OPA re-verification (RQ3).
- **Settings & Observability (`/settings`)**: Inspect API base URLs, OpenTelemetry browser tracing, Web Vitals metrics, and toggle **Interactive Thesis Demo Mode**.

## Getting Started

```bash
cd frontend
yarn install
yarn dev
```

The development server starts at <http://127.0.0.1:5173> by default and proxies API requests to the FastAPI backend over `/api`.

### Interactive Thesis Demo Mode (Zero-Overhead)

To explore or demo the complete compliance workbench without needing live Neo4j, FAISS, or LLM backend containers:
- Visit **`http://127.0.0.1:5173/?demo=true`** or toggle **Demo Mode** in `/settings`.
- Populates realistic OWASP Benchmark violations (Weak Hash MD5/SHA-1, Weak DES/ECB Crypto, SQL Injection CWE-89, Path Traversal CWE-22), multi-hop call-graph hierarchies, virtual diff previews, and dry-run verification.

### Environment

| Variable | Purpose | Default |
| --- | --- | --- |
| `VITE_API_BASE_URL` | Browser-visible API base override | `/api` |
| `CODEGRAPH_DEV_PROXY_TARGET` | Vite dev-server proxy target | `http://127.0.0.1:8000` |
| `VITE_OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP/HTTP collector URL for browser spans (Tempo/Jaeger/Honeycomb). Console exporter when unset. | _unset_ |
| `VITE_OTEL_DISABLED` | Set to `true` to disable browser tracing entirely. | _unset_ |

### Available Scripts

- `yarn dev` – start the Vite dev server.
- `yarn build` – type-check (`tsc`) and create an optimized production build in `dist/`.
- `yarn preview` – serve the production build locally (`http://0.0.0.0:4173`).
- `yarn lint` – run ESLint with `--max-warnings 0`.
- `yarn test` – run the Vitest unit suite (50+ tests).
- `yarn test:e2e:thesis` – run the Playwright end-to-end accessibility and thesis pipeline smoke tests.

## Project Structure

```text
frontend/
  src/
    pages/        # Overview (HomePage), UploadPage, PolicyPage, SettingsPage
    components/
      common/       # Layout, SidebarNav, Breadcrumbs, HealthStatus, ErrorBoundary, ActivityTray
      features/     # Policy evaluation workbench (ControlsPanel, SummaryCards, ViolationGroupTable, FindingDetailPanel, ConfidenceBand, RemediationConfirmDialog)
      ui/           # Headless primitives (button, badge, card, input, switch, CodeHighlight)
    hooks/        # Per-resource React Query hooks (e.g. usePolicyArtifacts, useUploadStatusStream)
    lib/
      api.ts          # Typed fetch client with built-in Interactive Demo Mode fallback
      demoData.ts     # Realistic OWASP benchmark demo fixtures & diffs
      schemas.ts      # Zod wire boundary schemas
      persistence.ts  # IndexedDB persistence (idb-keyval) for large eval payloads
      dependencies.ts # Smart engine dependency product definitions
      runtimeConfig.ts# Runtime base-URL resolution (window/meta/env/default)
      observability.ts# reportError + reportMetric event bus
      tracing.ts      # Browser OpenTelemetry (FetchInstrumentation, OTLP/console exporter)
    store/        # Zustand stores (e.g. activity)
```

### Data and state architecture
- **Wire validation:** every API response is parsed through a Zod schema. The
  unified `parseApiResponse` accepts structured-error envelopes on 4xx, rejects
  schema drift on 2xx (caught by the route-level ErrorBoundary).
- **Server state:** TanStack Query, with one cache key per resource id
  (`["policy", "explain", id]`, etc.). Mutations carry per-call `AbortController`s.
- **Client state:** Zustand stores with shallow-selector reads (see
  `store/activity.ts`). Persistent UI state is in IndexedDB via `idb-keyval`.
- **Routing:** React Router v7 with `lazy()` route splitting and a shared
  Suspense/ErrorBoundary at the route root.
- **A11y primitives:** Radix Dialog/Switch for WCAG-correct focus, scroll lock,
  and keyboard handling. `@axe-core/react` runs in dev. Playwright + axe-core
  cover e2e a11y.
- **Observability:** `reportError` / `reportMetric` (with Web Vitals: LCP, INP,
  CLS, FCP, TTFB) dispatch `codegraph:error` / `codegraph:metric` window events
  for a future telemetry sink to subscribe.
- **Distributed tracing:** `lib/tracing.ts` configures a `WebTracerProvider`
  with a `ZoneContextManager`. `FetchInstrumentation` injects a `traceparent`
  header into every API-origin request (scoped via `getRuntimeApiBase`) so
  the FastAPI `FastAPIInstrumentor` chains spans server-side. Console
  exporter by default; OTLP/HTTP when `VITE_OTEL_EXPORTER_OTLP_ENDPOINT` is
  set. Dynamically imported at boot (~31 kB gz, separate chunk).
- **Live observability surface:** the `/settings` page surfaces the
  resolved tracing state (on/disabled, exporter target) so you can see at
  a glance whether traceparent is being injected.
