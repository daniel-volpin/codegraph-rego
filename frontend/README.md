# CodeGraph Frontend

This Vite + React (TypeScript) client surfaces the main workflows exposed by the FastAPI backend:

- Upload Java projects and trigger ingestion/embedding.
- Run semantic + graph searches over the indexed codebase.
- Evaluate ISO 27001 policies and optionally enrich violations with LLM insights.

## Getting Started

```bash
cd frontend
yarn install
yarn dev
```

The development server starts at <http://127.0.0.1:5173> by default and proxies API requests to the FastAPI backend over `/api`, so ensure the API is running locally on <http://127.0.0.1:8000> unless you override the dev proxy target.

### Environment

| Variable | Purpose | Default |
| --- | --- | --- |
| `VITE_API_BASE_URL` | Browser-visible API base override | `/api` |
| `CODEGRAPH_DEV_PROXY_TARGET` | Vite dev-server proxy target | `http://127.0.0.1:8000` |
| `VITE_OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP/HTTP collector URL for browser spans (Tempo/Jaeger/Honeycomb). Console exporter when unset. | _unset_ |
| `VITE_OTEL_DISABLED` | Set to `true` to disable browser tracing entirely. | _unset_ |

Create a `.env` file in `frontend/` to override the default:

```bash
echo 'CODEGRAPH_DEV_PROXY_TARGET=http://localhost:9000' > .env
```

### Available Scripts

- `yarn dev` – start the Vite dev server.
- `yarn build` – type-check and create a production build.
- `yarn preview` – serve the build output locally.
- `yarn lint` – run eslint with `--max-warnings 0`.
- `yarn test` – run the Vitest unit suite (`yarn test:watch` for watch mode).
- `yarn test:e2e` – run the Playwright end-to-end suite (`yarn test:e2e:thesis` for the `@thesis`-tagged subset).

## Project Structure

```init
frontend/
  src/
    pages/        # Upload, search, policy, settings, home
    components/
      common/       # Layout, sidebar, breadcrumbs, error boundary, activity tray
      features/     # Page-specific feature modules (policy, search)
      ui/           # Headless primitives (button, badge, card, dialog, switch, ...)
    hooks/        # Per-resource React Query hooks (e.g. usePolicyArtifacts, useUploadStatusStream)
    lib/
      api.ts          # Typed fetch client; one unified parseApiResponse over Zod schemas
      schemas.ts      # Zod schemas at the wire boundary; types inferred via z.infer
      types.ts        # Re-export surface for inferred types
      persistence.ts  # IndexedDB persistence (idb-keyval) for large eval payloads
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
